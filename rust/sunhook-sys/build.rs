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
   let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
   let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
   let android = target_os == "android";
   let darwin = target_os == "macos";
   let windows = target_os == "windows";
   assert!(
      android
         || darwin
         || (target_os == "linux" && target_env == "gnu")
         || (windows && matches!(target_env.as_str(), "gnu" | "msvc")),
      "sunhook only supports Android, glibc Linux, Windows and macOS, not {target_os} {target_env}"
   );
   assert!(
      !darwin || target_arch == "aarch64",
      "sunhook only supports aarch64 on macOS, not {target_arch}"
   );
   assert!(
      !windows || target_arch == "x86_64",
      "sunhook only supports x86_64 on Windows, not {target_arch}"
   );

   let arch = match target_arch.as_str() {
      "aarch64" => "arm64",
      "arm" => "arm",
      "x86" | "x86_64" => "x86",
      other => panic!("sunhook only supports arm, aarch64, x86 and x86_64, not {other}"),
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

   if windows {
      // windows/include shadows the POSIX headers mingw lacks.
      build.include(src.join("windows/include"));
      if target_env == "msvc" {
         // cl.exe rejects the GNU inline asm and the .S glue.
         build.compiler("clang-cl").include(src.join("windows/msvc"));
         // clang-cl -Fo leaves the preprocessed .S as <name>.asm in the working directory.
         env::set_current_dir(env::var_os("OUT_DIR").unwrap()).expect("entering OUT_DIR");
      }
   } else if !android && !darwin {
      // gcc turns the 16-byte instruction write into a libatomic call that may take a lock.
      build.compiler("clang").define("_GNU_SOURCE", None);
   }

   // sh_jni.c defines JNI_OnLoad, which would collide with the embedding
   // library's own. darwin/ replaces the ELF linker and signal-based thread
   // parking.
   let skipped: &[&str] = if windows {
      &[
         "sh_jni.c",
         "sh_linker.c",
         "sh_elf.c",
         "sh_xdl.c",
         "sh_fixup.c",
         "bytesig.c",
      ]
   } else if darwin {
      &[
         "sh_jni.c",
         "sh_linker.c",
         "sh_elf.c",
         "sh_xdl.c",
         "sh_fixup.c",
      ]
   } else {
      &["sh_jni.c"]
   };
   let kept = |path: &PathBuf| {
      path
         .file_name()
         .and_then(|name| name.to_str())
         .is_some_and(|name| !skipped.contains(&name))
   };

   build
      .files(sources(&src, &["c"]).into_iter().filter(kept))
      .files(sources(&src.join("arch").join(arch), &["c", "S"]))
      .files(
         sources(&src.join("common"), &["c"])
            .into_iter()
            .filter(kept),
      );

   if darwin {
      build.files(sources(&src.join("darwin"), &["c"]));
   } else if windows {
      build.files(sources(&src.join("windows"), &["c"]));
   } else {
      build.files(sources(&src.join("third_party/xdl"), &["c"]));
   }
   build.compile("shadowhook");

   println!("cargo:include={}", src.join("include").display());

   if android {
      println!("cargo:rustc-link-lib=log");
      link_compiler_rt();
      build_nothing(&src);
   }
}

/// shadowhook calls `__clear_cache`, which Rust's `compiler_builtins` does not
/// provide on Android and rustc links with `-nodefaultlibs`.
fn link_compiler_rt() {
   let mut query = cc::Build::new().get_compiler().to_command();
   query.args(["--rtlib=compiler-rt", "-print-libgcc-file-name"]);
   let output = query
      .output()
      .unwrap_or_else(|err| panic!("running {query:?}: {err}"));
   assert!(
      output.status.success(),
      "{query:?} failed with {}",
      output.status
   );

   let archive = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
   let name = archive
      .file_stem()
      .and_then(|stem| stem.to_str())
      .and_then(|stem| stem.strip_prefix("lib"))
      .unwrap_or_else(|| panic!("unexpected compiler-rt path {}", archive.display()));
   println!(
      "cargo:rustc-link-search=native={}",
      archive.parent().unwrap().display()
   );
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
fn build_nothing(src: &Path) {
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

   if env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64" {
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
