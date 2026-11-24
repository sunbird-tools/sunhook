use std::{
   env,
   fs,
   path::{
      Path,
      PathBuf,
   },
   process::Command,
};

const NOTHING_NAME: &str = "libshadowhook_nothing.so";

fn sources(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
   let mut found: Vec<PathBuf> = fs::read_dir(dir)
      .unwrap_or_else(|err| panic!("reading {}: {err}", dir.display()))
      .map(|entry| entry.expect("reading directory entry").path())
      .filter(|path| {
         path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext))
      })
      .collect();
   found.sort();
   found
}

fn main() {
   let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
   let src = manifest_dir.join("../../shadowhook/src/main/cpp");
   println!("cargo:rerun-if-changed={}", src.display());

   let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
   let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
   assert!(
      target_os == "android",
      "sunhook only supports Android, not {target_os}"
   );

   let arch = match target_arch.as_str() {
      "aarch64" => "arm64",
      "arm" => "arm",
      "x86_64" => "x86_64",
      other => panic!("sunhook only supports arm, aarch64 and x86_64, not {other}"),
   };

   let mut build = cc::Build::new();
   build.std("c11").opt_level_str("s").warnings(false);

   for include in [
      ".",
      "include",
      &format!("arch/{arch}"),
      "common",
      "third_party/xdl",
      "third_party/bsd",
      "third_party/lss",
   ] {
      build.include(src.join(include));
   }

   // sh_jni.c defines JNI_OnLoad, which would collide with the embedding
   // library's own.
   let top_level = sources(&src, &["c"])
      .into_iter()
      .filter(|path| path.file_name().is_some_and(|name| name != "sh_jni.c"));

   build
      .files(top_level)
      .files(sources(&src.join("arch").join(arch), &["c", "S"]))
      .files(sources(&src.join("common"), &["c"]))
      .files(sources(&src.join("third_party/xdl"), &["c"]))
      .compile("shadowhook");

   println!("cargo:rustc-link-lib=log");
   println!("cargo:include={}", src.join("include").display());
   link_compiler_rt();

   build_nothing(&src, arch);
}

/// shadowhook calls `__clear_cache`, which Rust's `compiler_builtins` does not
/// provide on Android and rustc links with `-nodefaultlibs`.
fn link_compiler_rt() {
   let mut query = cc::Build::new().get_compiler().to_command();
   query.args(["--rtlib=compiler-rt", "-print-libgcc-file-name"]);
   let output = query
      .output()
      .unwrap_or_else(|err| panic!("running {query:?}: {err}"));
   assert!(output.status.success(), "{query:?} failed with {}", output.status);

   let archive = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
   let name = archive
      .file_stem()
      .and_then(|stem| stem.to_str())
      .and_then(|stem| stem.strip_prefix("lib"))
      .unwrap_or_else(|| panic!("unexpected compiler-rt path {}", archive.display()));
   println!("cargo:rustc-link-search=native={}", archive.parent().unwrap().display());
   println!("cargo:rustc-link-lib=static={name}");
}

fn run(mut command: Command) {
   let status = command
      .status()
      .unwrap_or_else(|err| panic!("running {command:?}: {err}"));
   assert!(status.success(), "{command:?} failed with {status}");
}

/// `shadowhook_init()` dlopen()s this library by basename to locate soinfo
/// fields, so it has to ship in the APK next to the library that embeds
/// sunhook.
fn build_nothing(src: &Path, arch: &str) {
   let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
   let nothing = out_dir.join(NOTHING_NAME);
   let mut link = cc::Build::new().get_compiler().to_command();
   link.args([
      "-shared",
      "-Oz",
      "-fno-ident",
      "-fno-unwind-tables",
      "-fno-asynchronous-unwind-tables",
      "-nostdlib",
      "-nostartfiles",
      "-nodefaultlibs",
      "-Wl,--strip-all",
      "-Wl,--as-needed",
      "-Wl,--hash-style=sysv",
      "-Wl,--build-id=none",
   ]);

   if arch != "arm" {
      link.arg("-Wl,-z,max-page-size=16384");
   }

   link
      .arg(format!("-Wl,-soname,{NOTHING_NAME}"))
      .arg(src.join("nothing/sh_nothing.c"))
      .arg("-o")
      .arg(&nothing);
   run(link);

   println!("cargo:nothing={}", nothing.display());

   let target = env::var_os("TARGET").unwrap();
   let Some(profile_dir) = out_dir
      .ancestors()
      .find(|dir| dir.parent().and_then(Path::file_name) == Some(target.as_os_str()))
   else {
      println!(
         "cargo:warning={NOTHING_NAME} is at {}, package it next to the final library",
         nothing.display()
      );
      return;
   };

   fs::copy(&nothing, profile_dir.join(NOTHING_NAME))
      .unwrap_or_else(|err| panic!("copying {NOTHING_NAME} to {}: {err}", profile_dir.display()));
}
