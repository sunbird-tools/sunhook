//! Runs on an Android device or emulator, with `libshadowhook_nothing.so`
//! reachable through `LD_LIBRARY_PATH`.

use std::{
   ffi::{
      CStr,
      CString,
      c_char,
      c_void,
   },
   fs::{
      self,
      File,
   },
   hint::black_box,
   os::fd::AsFd,
   ptr::NonNull,
   sync::{
      Arc,
      Mutex,
      Once,
      atomic::{
         AtomicU32,
         AtomicU64,
         Ordering,
      },
   },
};

use sunhook::{
   Mode,
   RecordName,
   Target,
   hook::{
      self,
      FnPtr,
      Orig,
      StackScope,
   },
   intercept::{
      self,
      CpuContext,
      Fpsimd,
   },
   linker::Library,
   record::{
      self,
      Items,
   },
};

type Unary = extern "C" fn(i32) -> i32;

#[cfg(target_pointer_width = "32")]
type Reg = u32;
#[cfg(target_pointer_width = "64")]
type Reg = u64;

/// x86 passes it on the stack above the return address.
#[cfg(target_arch = "x86")]
fn arg0(ctx: &mut CpuContext) -> &mut Reg {
   unsafe { &mut *((ctx.regs[4] as usize + 4) as *mut Reg) }
}

#[cfg(not(target_arch = "x86"))]
const fn arg0(ctx: &mut CpuContext) -> &mut Reg {
   &mut ctx.regs[if cfg!(target_arch = "x86_64") { 7 } else { 0 }]
}

fn init() {
   static INIT: Once = Once::new();
   INIT.call_once(|| {
      sunhook::init(Mode::Shared, true).expect("shadowhook_init");
      sunhook::set_recordable(true);
   });
}

fn addr(f: Unary) -> NonNull<c_void> {
   NonNull::new(f as *mut c_void).unwrap()
}

/// Calls through a pointer the optimizer cannot see, so every call reaches the
/// patched entry.
fn call(f: Unary, x: i32) -> i32 {
   black_box(f)(x)
}

fn dlopen(name: &CStr) -> NonNull<c_void> {
   NonNull::new(unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW) }).expect("dlopen")
}

macro_rules! target_fn {
   ($name:ident, $mul:literal, $add:literal) => {
      #[inline(never)]
      const extern "C" fn $name(x: i32) -> i32 {
         let x = black_box(x).wrapping_mul(black_box($mul));
         black_box(x.wrapping_add(black_box($add)) ^ black_box(0))
      }
   };
}

target_fn!(shared_target, 3, 1);
static SHARED_OUTER: AtomicU32 = AtomicU32::new(0);
static SHARED_INNER: AtomicU32 = AtomicU32::new(0);

extern "C" fn shared_outer(x: i32) -> i32 {
   let scope = unsafe { StackScope::enter(shared_outer as Unary) };
   SHARED_OUTER.fetch_add(1, Ordering::Relaxed);
   // Calling prev twice fails if the inner proxy popped this call's frame on
   // its way out.
   scope.prev()(x) + scope.prev()(x)
}

extern "C" fn shared_inner(x: i32) -> i32 {
   let scope = unsafe { StackScope::enter(shared_inner as Unary) };
   SHARED_INNER.fetch_add(1, Ordering::Relaxed);
   scope.prev()(x + 100)
}

#[test]
fn shared_chain_pops_only_at_entry_proxy() {
   init();
   let inner = unsafe {
      hook::hook(
         Target::func(addr(shared_target)),
         shared_inner as Unary,
         None,
         None,
      )
   }
   .unwrap();
   let outer = unsafe {
      hook::hook(
         Target::func(addr(shared_target)),
         shared_outer as Unary,
         None,
         None,
      )
   }
   .unwrap();

   for round in 1..=3 {
      assert_eq!(call(shared_target, 1), 2 * (101 * 3 + 1));
      assert_eq!(SHARED_OUTER.load(Ordering::Relaxed), round);
      assert_eq!(SHARED_INNER.load(Ordering::Relaxed), 2 * round);
   }

   outer.unhook().unwrap();
   inner.unhook().unwrap();
   assert_eq!(call(shared_target, 1), 4);
}

target_fn!(recursive_target, 5, 2);
static RECURSIVE_CALLS: AtomicU32 = AtomicU32::new(0);

extern "C" fn recursive_proxy(x: i32) -> i32 {
   let scope = unsafe { StackScope::enter(recursive_proxy as Unary) };
   RECURSIVE_CALLS.fetch_add(1, Ordering::Relaxed);
   if x > 0 {
      return call(recursive_target, x - 1) + 1000;
   }
   scope.prev()(x)
}

#[test]
fn shared_recursion_skips_proxy() {
   init();
   let hook = unsafe {
      hook::hook(
         Target::func(addr(recursive_target)),
         recursive_proxy as Unary,
         None,
         None,
      )
   }
   .unwrap();

   assert_eq!(call(recursive_target, 1), 2 + 1000);
   assert_eq!(RECURSIVE_CALLS.load(Ordering::Relaxed), 1);
   assert_eq!(call(recursive_target, 1), 2 + 1000);
   assert_eq!(RECURSIVE_CALLS.load(Ordering::Relaxed), 2);

   hook.unhook().unwrap();
}

target_fn!(reentrant_target, 7, 3);
static REENTRANT_CALLS: AtomicU32 = AtomicU32::new(0);

extern "C" fn reentrant_proxy(x: i32) -> i32 {
   let scope = unsafe { StackScope::enter(reentrant_proxy as Unary) };
   REENTRANT_CALLS.fetch_add(1, Ordering::Relaxed);
   if x > 0 {
      scope.allow_reentrant();
      let result = call(reentrant_target, x - 1);
      scope.disallow_reentrant();
      return result + 1000;
   }
   scope.prev()(x)
}

#[test]
fn shared_allow_reentrant() {
   init();
   let hook = unsafe {
      hook::hook(
         Target::func(addr(reentrant_target)),
         reentrant_proxy as Unary,
         None,
         None,
      )
   }
   .unwrap();

   assert_eq!(call(reentrant_target, 2), 3 + 2000);
   assert_eq!(REENTRANT_CALLS.load(Ordering::Relaxed), 3);

   hook.unhook().unwrap();
}

target_fn!(unique_target, 11, 4);
static UNIQUE_ORIG: Orig<Unary> = Orig::new();

extern "C" fn unique_proxy(x: i32) -> i32 {
   UNIQUE_ORIG.get()(x) + 1
}

#[test]
fn unique_calls_orig_and_rejects_second_hook() {
   init();
   let hook = unsafe {
      hook::hook(
         Target::func(addr(unique_target)),
         unique_proxy as Unary,
         Some(&UNIQUE_ORIG),
         Some(Mode::Unique),
      )
   }
   .unwrap();
   assert!(!hook.is_pending());
   assert_eq!(call(unique_target, 2), 26 + 1);

   let second = unsafe {
      hook::hook(
         Target::func(addr(unique_target)),
         unique_proxy as Unary,
         None,
         Some(Mode::Unique),
      )
   };
   assert!(second.is_err());

   hook.unhook().unwrap();
   assert_eq!(call(unique_target, 2), 26);
}

target_fn!(multi_target, 13, 5);
static MULTI_ORIG_A: Orig<Unary> = Orig::new();
static MULTI_ORIG_B: Orig<Unary> = Orig::new();
static MULTI_ORIG_C: Orig<Unary> = Orig::new();

extern "C" fn multi_a(x: i32) -> i32 {
   MULTI_ORIG_A.get()(x) + 1
}

extern "C" fn multi_b(x: i32) -> i32 {
   MULTI_ORIG_B.get()(x) + 10
}

extern "C" fn multi_c(x: i32) -> i32 {
   MULTI_ORIG_C.get()(x) + 100
}

#[test]
fn multi_chain_survives_middle_unhook() {
   init();
   let install = |proxy: Unary, orig: &'static Orig<Unary>| {
      unsafe {
         hook::hook(
            Target::func(addr(multi_target)),
            proxy,
            Some(orig),
            Some(Mode::Multi),
         )
      }
      .unwrap()
   };
   let a = install(multi_a, &MULTI_ORIG_A);
   let b = install(multi_b, &MULTI_ORIG_B);
   let c = install(multi_c, &MULTI_ORIG_C);
   assert_eq!(call(multi_target, 1), 18 + 111);

   b.unhook().unwrap();
   assert_eq!(call(multi_target, 1), 18 + 101);

   a.unhook().unwrap();
   c.unhook().unwrap();
   assert_eq!(call(multi_target, 1), 18);
}

target_fn!(intercept_target, 17, 6);

#[test]
fn intercept_rewrites_argument_register() {
   init();
   let seen = Arc::new(AtomicU64::new(0));
   let seen_in = Arc::clone(&seen);
   let intercept = unsafe {
      intercept::intercept(
         Target::func(addr(intercept_target)),
         move |ctx| {
            #[allow(
               clippy::useless_conversion,
               reason = "regs is u32 on arm and u64 on aarch64"
            )]
            seen_in.store(u64::from(*arg0(ctx)), Ordering::Relaxed);
            *arg0(ctx) = 2;
         },
         Fpsimd::Off,
      )
   }
   .unwrap();

   assert_eq!(call(intercept_target, 9), 17 * 2 + 6);
   assert_eq!(seen.load(Ordering::Relaxed), 9);

   intercept.unintercept().unwrap();
   assert_eq!(call(intercept_target, 9), 17 * 9 + 6);
}

target_fn!(record_target, 19, 7);
static RECORD_ORIG: Orig<Unary> = Orig::new();

extern "C" fn record_proxy(x: i32) -> i32 {
   RECORD_ORIG.get()(x)
}

#[test]
fn record_names_reach_the_log() {
   init();
   let hook = unsafe {
      hook::hook(
         Target::FuncAddr {
            addr:   addr(record_target),
            record: Some(RecordName {
               lib: c"libsunhooktest.so",
               sym: c"record_target_sym",
            }),
         },
         record_proxy as Unary,
         Some(&RECORD_ORIG),
         Some(Mode::Unique),
      )
   }
   .unwrap();

   let log = record::records(Items::LIB_NAME | Items::SYM_NAME | Items::OP).unwrap();
   assert!(log.contains("libsunhooktest.so,record_target_sym"), "{log}");

   let path = std::env::temp_dir().join(format!("sunhook-dump-{}", std::process::id()));
   let file = File::create(&path).unwrap();
   record::dump(file.as_fd(), Items::LIB_NAME | Items::SYM_NAME);
   drop(file);
   let dumped = fs::read_to_string(&path).unwrap();
   fs::remove_file(&path).unwrap();
   assert!(
      dumped.contains("libsunhooktest.so,record_target_sym"),
      "{dumped}"
   );

   hook.unhook().unwrap();
}

type ZlibVersion = unsafe extern "C" fn() -> *const c_char;

const extern "C" fn zlib_version_proxy() -> *const c_char {
   c"sunhook".as_ptr()
}

#[test]
#[cfg_attr(not(target_os = "android"), ignore = "glibc builds have no load monitor")]
fn pending_sym_name_hooks_on_dlopen() {
   init();
   assert!(
      Library::open(c"libz.so").is_none(),
      "libz.so is already loaded"
   );

   let resolved = Arc::new(Mutex::new(Vec::new()));
   let resolved_in = Arc::clone(&resolved);
   let hook = unsafe {
      hook::hook(
         Target::SymName {
            lib:     c"libz.so",
            sym:     c"zlibVersion",
            on_done: Some(Box::new(move |result| {
               resolved_in
                  .lock()
                  .unwrap()
                  .push(result.map(|sym| sym.as_ptr() as usize));
            })),
         },
         zlib_version_proxy as ZlibVersion,
         None,
         Some(Mode::Unique),
      )
   }
   .unwrap();
   assert!(hook.is_pending());

   let handle = dlopen(c"libz.so");
   let sym = unsafe { libc::dlsym(handle.as_ptr(), c"zlibVersion".as_ptr()) };
   assert_eq!(*resolved.lock().unwrap(), [Ok(sym as usize)]);

   let zlib_version = unsafe { ZlibVersion::from_addr(NonNull::new(sym).unwrap()) };
   assert_eq!(unsafe { CStr::from_ptr(zlib_version()) }, c"sunhook");
   hook.unhook().unwrap();
   assert_ne!(unsafe { CStr::from_ptr(zlib_version()) }, c"sunhook");
}

#[test]
#[cfg(not(target_vendor = "apple"))]
#[cfg_attr(not(target_os = "android"), ignore = "glibc builds have no load monitor")]
fn dl_callbacks_see_load_and_unload() {
   use sunhook::linker::{
      DlCallback,
      Phase,
   };

   init();
   assert!(
      Library::open(c"libsync.so").is_none(),
      "libsync.so is already loaded"
   );

   let events = Arc::new(Mutex::new(Vec::new()));
   let watch = |kind: &'static str| {
      let events = Arc::clone(&events);
      move |phase: Phase, info: &libc::dl_phdr_info| {
         let name = unsafe { CStr::from_ptr(info.dlpi_name) };
         if name.to_bytes().ends_with(b"/libsync.so") {
            events.lock().unwrap().push((kind, phase));
         }
      }
   };
   let on_init = DlCallback::on_init(watch("init")).unwrap();
   let on_fini = DlCallback::on_fini(watch("fini")).unwrap();

   let handle = dlopen(c"libsync.so");
   assert_eq!(unsafe { libc::dlclose(handle.as_ptr()) }, 0);
   on_init.unregister().unwrap();
   on_fini.unregister().unwrap();

   assert_eq!(*events.lock().unwrap(), [
      ("init", Phase::Pre),
      ("init", Phase::Post),
      ("fini", Phase::Pre),
      ("fini", Phase::Post),
   ]);
}

// Five adds of 1, 2, 4, 8 and 16 to the first argument, each an
// INSTR_LEN byte instruction, so the second one sits at a known offset in the
// middle of the function.
const INSTR_LEN: usize = if cfg!(target_arch = "x86") { 5 } else { 4 };

// Private extern stays in the Mach-O symbol table and out of the export trie.
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
std::arch::global_asm!(
   ".text",
   ".globl _sunhook_instr_target",
   ".private_extern _sunhook_instr_target",
   ".p2align 2",
   "_sunhook_instr_target:",
   "add x0, x0, #1",
   "add x0, x0, #2",
   "add x0, x0, #4",
   "add x0, x0, #8",
   "add x0, x0, #16",
   "ret",
);

#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
std::arch::global_asm!(
   ".text",
   ".globl sunhook_instr_target",
   ".type sunhook_instr_target, %function",
   ".p2align 2",
   "sunhook_instr_target:",
   "add x0, x0, #1",
   "add x0, x0, #2",
   "add x0, x0, #4",
   "add x0, x0, #8",
   "add x0, x0, #16",
   "ret",
   ".size sunhook_instr_target, . - sunhook_instr_target",
);

#[cfg(target_arch = "arm")]
std::arch::global_asm!(
   ".text",
   ".syntax unified",
   ".thumb",
   ".globl sunhook_instr_target",
   ".type sunhook_instr_target, %function",
   ".thumb_func",
   ".p2align 2",
   "sunhook_instr_target:",
   "add.w r0, r0, #1",
   "add.w r0, r0, #2",
   "add.w r0, r0, #4",
   "add.w r0, r0, #8",
   "add.w r0, r0, #16",
   "bx lr",
   ".size sunhook_instr_target, . - sunhook_instr_target",
);

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
   ".text",
   ".globl sunhook_instr_target",
   ".type sunhook_instr_target, @function",
   ".p2align 4",
   "sunhook_instr_target:",
   "add rdi, 1",
   "add rdi, 2",
   "add rdi, 4",
   "add rdi, 8",
   "add rdi, 16",
   "mov eax, edi",
   "ret",
   ".size sunhook_instr_target, . - sunhook_instr_target",
);

#[cfg(target_arch = "x86")]
std::arch::global_asm!(
   ".text",
   ".globl sunhook_instr_target",
   ".type sunhook_instr_target, @function",
   ".p2align 4",
   "sunhook_instr_target:",
   "add dword ptr [esp + 4], 1",
   "add dword ptr [esp + 4], 2",
   "add dword ptr [esp + 4], 4",
   "add dword ptr [esp + 4], 8",
   "add dword ptr [esp + 4], 16",
   "mov eax, [esp + 4]",
   "ret",
   ".size sunhook_instr_target, . - sunhook_instr_target",
);

unsafe extern "C" {
   fn sunhook_instr_target(x: i32) -> i32;
}

#[test]
fn intercept_instr_mid_function() {
   init();
   let entry = sunhook_instr_target as unsafe extern "C" fn(i32) -> i32;
   let second = NonNull::new(entry.addr().wrapping_byte_add(INSTR_LEN)).unwrap();
   let intercept = unsafe {
      intercept::intercept_instr(
         second,
         None,
         |ctx| {
            assert_eq!(*arg0(ctx), 1);
            *arg0(ctx) = 100;
         },
         Fpsimd::Off,
      )
   }
   .unwrap();

   assert_eq!(unsafe { black_box(entry)(0) }, 100 + 2 + 4 + 8 + 16);
   intercept.unintercept().unwrap();
   assert_eq!(unsafe { black_box(entry)(0) }, 31);
}

#[test]
fn symtab_finds_symbols_missing_from_dynsym() {
   init();
   let exe = std::env::current_exe().unwrap();
   let name = CString::new(exe.file_name().unwrap().as_encoded_bytes()).unwrap();
   let elf = Library::open(&name).unwrap();
   let entry = sunhook_instr_target as unsafe extern "C" fn(i32) -> i32;

   assert_eq!(
      elf.symtab(c"sunhook_instr_target").map(NonNull::as_ptr),
      Some(entry.addr())
   );
   assert_eq!(elf.dynsym(c"sunhook_instr_target"), None);
   assert_eq!(
      elf.sym(c"sunhook_instr_target").map(NonNull::as_ptr),
      Some(entry.addr())
   );
}
