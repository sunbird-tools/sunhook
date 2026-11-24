//! Raw bindings to `shadowhook.h` from the sunhook fork of shadowhook.
//!
//! The C library is compiled from `shadowhook/src/main/cpp` by this crate's
//! build script.

#![no_std]
#![allow(non_camel_case_types)]

use core::ffi::{
   c_char,
   c_int,
   c_void,
};

use libc::{
   dl_phdr_info,
   size_t,
};

pub const SHADOWHOOK_ERRNO_OK: c_int = 0;
pub const SHADOWHOOK_ERRNO_PENDING: c_int = 1;
pub const SHADOWHOOK_ERRNO_UNINIT: c_int = 2;
pub const SHADOWHOOK_ERRNO_INVALID_ARG: c_int = 3;
pub const SHADOWHOOK_ERRNO_OOM: c_int = 4;
pub const SHADOWHOOK_ERRNO_MPROT: c_int = 5;
pub const SHADOWHOOK_ERRNO_WRITE_CRASH: c_int = 6;
pub const SHADOWHOOK_ERRNO_INIT_ERRNO: c_int = 7;
pub const SHADOWHOOK_ERRNO_INIT_SIGSEGV: c_int = 8;
pub const SHADOWHOOK_ERRNO_INIT_SIGBUS: c_int = 9;
pub const SHADOWHOOK_ERRNO_INTERCEPT_DUP: c_int = 10;
pub const SHADOWHOOK_ERRNO_INIT_SAFE: c_int = 11;
pub const SHADOWHOOK_ERRNO_INIT_LINKER: c_int = 12;
pub const SHADOWHOOK_ERRNO_INIT_HUB: c_int = 13;
pub const SHADOWHOOK_ERRNO_HUB_CREAT: c_int = 14;
pub const SHADOWHOOK_ERRNO_MONITOR_DLOPEN: c_int = 15;
pub const SHADOWHOOK_ERRNO_HOOK_UNIQUE_DUP: c_int = 16;
pub const SHADOWHOOK_ERRNO_HOOK_DLOPEN_CRASH: c_int = 17;
pub const SHADOWHOOK_ERRNO_HOOK_DLSYM: c_int = 18;
pub const SHADOWHOOK_ERRNO_HOOK_DLSYM_CRASH: c_int = 19;
pub const SHADOWHOOK_ERRNO_HOOK_DUP: c_int = 20;
pub const SHADOWHOOK_ERRNO_HOOK_DLADDR_CRASH: c_int = 21;
pub const SHADOWHOOK_ERRNO_HOOK_DLINFO: c_int = 22;
pub const SHADOWHOOK_ERRNO_HOOK_SYMSZ: c_int = 23;
pub const SHADOWHOOK_ERRNO_HOOK_ENTER: c_int = 24;
pub const SHADOWHOOK_ERRNO_HOOK_REWRITE_CRASH: c_int = 25;
pub const SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED: c_int = 26;
pub const SHADOWHOOK_ERRNO_UNHOOK_NOTFOUND: c_int = 27;
pub const SHADOWHOOK_ERRNO_UNHOOK_CMP_CRASH: c_int = 28;
pub const SHADOWHOOK_ERRNO_UNHOOK_TRAMPO_MISMATCH: c_int = 29;
pub const SHADOWHOOK_ERRNO_UNHOOK_EXIT_MISMATCH: c_int = 30;
pub const SHADOWHOOK_ERRNO_UNHOOK_EXIT_CRASH: c_int = 31;
pub const SHADOWHOOK_ERRNO_UNHOOK_ON_ERROR: c_int = 32;
pub const SHADOWHOOK_ERRNO_UNHOOK_ON_UNFINISHED: c_int = 33;
pub const SHADOWHOOK_ERRNO_ELF_ARCH_MISMATCH: c_int = 34;
pub const SHADOWHOOK_ERRNO_LINKER_ARCH_MISMATCH: c_int = 35;
pub const SHADOWHOOK_ERRNO_DUP: c_int = 36;
pub const SHADOWHOOK_ERRNO_NOT_FOUND: c_int = 37;
pub const SHADOWHOOK_ERRNO_NOT_SUPPORT: c_int = 38;
pub const SHADOWHOOK_ERRNO_INIT_TASK: c_int = 39;
pub const SHADOWHOOK_ERRNO_HOOK_ISLAND_EXIT: c_int = 40;
pub const SHADOWHOOK_ERRNO_HOOK_ISLAND_ENTER: c_int = 41;
pub const SHADOWHOOK_ERRNO_HOOK_ISLAND_REWRITE: c_int = 42;
pub const SHADOWHOOK_ERRNO_MODE_CONFLICT: c_int = 43;
pub const SHADOWHOOK_ERRNO_HOOK_MULTI_DUP: c_int = 44;
pub const SHADOWHOOK_ERRNO_DISABLED: c_int = 45;

pub type shadowhook_mode_t = c_int;
pub const SHADOWHOOK_MODE_SHARED: shadowhook_mode_t = 0;
pub const SHADOWHOOK_MODE_UNIQUE: shadowhook_mode_t = 1;
pub const SHADOWHOOK_MODE_MULTI: shadowhook_mode_t = 2;

pub const SHADOWHOOK_HOOK_DEFAULT: u32 = 0;
pub const SHADOWHOOK_HOOK_WITH_SHARED_MODE: u32 = 1;
pub const SHADOWHOOK_HOOK_WITH_UNIQUE_MODE: u32 = 2;
pub const SHADOWHOOK_HOOK_WITH_MULTI_MODE: u32 = 4;
pub const SHADOWHOOK_HOOK_RECORD: u32 = 8;

pub const SHADOWHOOK_INTERCEPT_DEFAULT: u32 = 0;
pub const SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_ONLY: u32 = 1;
pub const SHADOWHOOK_INTERCEPT_WITH_FPSIMD_WRITE_ONLY: u32 = 2;
pub const SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_WRITE: u32 = 3;
pub const SHADOWHOOK_INTERCEPT_RECORD: u32 = 4;

pub const SHADOWHOOK_RECORD_ITEM_ALL: u32 = 0xFFFF_FFFF;
pub const SHADOWHOOK_RECORD_ITEM_TIMESTAMP: u32 = 1 << 0;
pub const SHADOWHOOK_RECORD_ITEM_CALLER_LIB_NAME: u32 = 1 << 1;
pub const SHADOWHOOK_RECORD_ITEM_OP: u32 = 1 << 2;
pub const SHADOWHOOK_RECORD_ITEM_LIB_NAME: u32 = 1 << 3;
pub const SHADOWHOOK_RECORD_ITEM_SYM_NAME: u32 = 1 << 4;
pub const SHADOWHOOK_RECORD_ITEM_SYM_ADDR: u32 = 1 << 5;
pub const SHADOWHOOK_RECORD_ITEM_NEW_ADDR: u32 = 1 << 6;
pub const SHADOWHOOK_RECORD_ITEM_BACKUP_LEN: u32 = 1 << 7;
pub const SHADOWHOOK_RECORD_ITEM_ERRNO: u32 = 1 << 8;
pub const SHADOWHOOK_RECORD_ITEM_STUB: u32 = 1 << 9;
pub const SHADOWHOOK_RECORD_ITEM_FLAGS: u32 = 1 << 10;
pub const SHADOWHOOK_RECORD_ITEM_TRACE: u32 = 1 << 11;

#[repr(C)]
#[derive(Clone, Copy)]
pub union shadowhook_vreg_t {
   #[cfg(target_arch = "aarch64")]
   pub q: u128,
   pub d: [u64; 2],
   pub s: [u32; 4],
   pub h: [u16; 8],
   pub b: [u8; 16],
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct shadowhook_cpu_context_t {
   /// x0 to x30.
   pub regs:   [u64; 31],
   pub sp:     u64,
   pub pc:     u64,
   pub pstate: u64,
   /// q0 to q31.
   pub vregs:  [shadowhook_vreg_t; 32],
   pub fpsr:   u64,
   pub fpcr:   u64,
}

#[cfg(target_arch = "arm")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct shadowhook_cpu_context_t {
   /// r0 to r15.
   pub regs:  [u32; 16],
   pub cpsr:  u32,
   pub fpscr: u32,
   /// q0 to q15 on NEON, `VFPv4` and `VFPv3-D32`. Only q0 to q7 are valid on
   /// `VFPv3-D16`.
   pub vregs: [shadowhook_vreg_t; 16],
}

pub type shadowhook_hooked_t = Option<
   unsafe extern "C" fn(
      error_number: c_int,
      lib_name: *const c_char,
      sym_name: *const c_char,
      sym_addr: *mut c_void,
      new_addr: *mut c_void,
      orig_addr: *mut c_void,
      arg: *mut c_void,
   ),
>;

pub type shadowhook_interceptor_t =
   Option<unsafe extern "C" fn(cpu_context: *mut shadowhook_cpu_context_t, data: *mut c_void)>;

pub type shadowhook_intercepted_t = Option<
   unsafe extern "C" fn(
      error_number: c_int,
      lib_name: *const c_char,
      sym_name: *const c_char,
      sym_addr: *mut c_void,
      pre: shadowhook_interceptor_t,
      data: *mut c_void,
      arg: *mut c_void,
   ),
>;

pub type shadowhook_dl_info_t =
   Option<unsafe extern "C" fn(info: *mut dl_phdr_info, size: size_t, data: *mut c_void)>;

unsafe extern "C" {
   pub fn shadowhook_get_version() -> *const c_char;

   pub fn shadowhook_init(default_mode: shadowhook_mode_t, debuggable: bool) -> c_int;
   pub fn shadowhook_get_init_errno() -> c_int;

   pub fn shadowhook_get_mode() -> shadowhook_mode_t;
   pub fn shadowhook_get_debuggable() -> bool;
   pub fn shadowhook_set_debuggable(debuggable: bool);
   pub fn shadowhook_get_recordable() -> bool;
   pub fn shadowhook_set_recordable(recordable: bool);
   pub fn shadowhook_get_disable() -> bool;
   pub fn shadowhook_set_disable(disable: bool);

   pub fn shadowhook_get_errno() -> c_int;
   pub fn shadowhook_to_errmsg(error_number: c_int) -> *const c_char;

   pub fn shadowhook_hook_func_addr(
      func_addr: *mut c_void,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
   ) -> *mut c_void;
   pub fn shadowhook_hook_sym_addr(
      sym_addr: *mut c_void,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
   ) -> *mut c_void;
   pub fn shadowhook_hook_sym_name(
      lib_name: *const c_char,
      sym_name: *const c_char,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
   ) -> *mut c_void;
   pub fn shadowhook_hook_sym_name_callback(
      lib_name: *const c_char,
      sym_name: *const c_char,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
      hooked: shadowhook_hooked_t,
      hooked_arg: *mut c_void,
   ) -> *mut c_void;
   pub fn shadowhook_unhook(stub: *mut c_void) -> c_int;

   /// With `SHADOWHOOK_HOOK_RECORD` in `flags`, takes `record_lib_name` and
   /// `record_sym_name` as two trailing `*const c_char` arguments.
   pub fn shadowhook_hook_func_addr_2(
      func_addr: *mut c_void,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
      flags: u32,
      ...
   ) -> *mut c_void;
   /// With `SHADOWHOOK_HOOK_RECORD` in `flags`, takes `record_lib_name` and
   /// `record_sym_name` as two trailing `*const c_char` arguments.
   pub fn shadowhook_hook_sym_addr_2(
      sym_addr: *mut c_void,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
      flags: u32,
      ...
   ) -> *mut c_void;
   pub fn shadowhook_hook_sym_name_2(
      lib_name: *const c_char,
      sym_name: *const c_char,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
      flags: u32,
   ) -> *mut c_void;
   pub fn shadowhook_hook_sym_name_callback_2(
      lib_name: *const c_char,
      sym_name: *const c_char,
      new_addr: *mut c_void,
      orig_addr: *mut *mut c_void,
      flags: u32,
      hooked: shadowhook_hooked_t,
      hooked_arg: *mut c_void,
   ) -> *mut c_void;

   /// With `SHADOWHOOK_INTERCEPT_RECORD` in `flags`, takes `record_lib_name`
   /// and `record_sym_name` as two trailing `*const c_char` arguments.
   pub fn shadowhook_intercept_instr_addr(
      instr_addr: *mut c_void,
      pre: shadowhook_interceptor_t,
      data: *mut c_void,
      flags: u32,
      ...
   ) -> *mut c_void;
   /// With `SHADOWHOOK_INTERCEPT_RECORD` in `flags`, takes `record_lib_name`
   /// and `record_sym_name` as two trailing `*const c_char` arguments.
   pub fn shadowhook_intercept_func_addr(
      func_addr: *mut c_void,
      pre: shadowhook_interceptor_t,
      data: *mut c_void,
      flags: u32,
      ...
   ) -> *mut c_void;
   /// With `SHADOWHOOK_INTERCEPT_RECORD` in `flags`, takes `record_lib_name`
   /// and `record_sym_name` as two trailing `*const c_char` arguments.
   pub fn shadowhook_intercept_sym_addr(
      sym_addr: *mut c_void,
      pre: shadowhook_interceptor_t,
      data: *mut c_void,
      flags: u32,
      ...
   ) -> *mut c_void;
   pub fn shadowhook_intercept_sym_name(
      lib_name: *const c_char,
      sym_name: *const c_char,
      pre: shadowhook_interceptor_t,
      data: *mut c_void,
      flags: u32,
   ) -> *mut c_void;
   pub fn shadowhook_intercept_sym_name_callback(
      lib_name: *const c_char,
      sym_name: *const c_char,
      pre: shadowhook_interceptor_t,
      data: *mut c_void,
      flags: u32,
      intercepted: shadowhook_intercepted_t,
      intercepted_arg: *mut c_void,
   ) -> *mut c_void;
   pub fn shadowhook_unintercept(stub: *mut c_void) -> c_int;

   /// Returns a `malloc`ed string, or null when recording is off or nothing
   /// matches.
   pub fn shadowhook_get_records(item_flags: u32) -> *mut c_char;
   pub fn shadowhook_dump_records(fd: c_int, item_flags: u32);

   pub fn shadowhook_dlopen(lib_name: *const c_char) -> *mut c_void;
   pub fn shadowhook_dlclose(handle: *mut c_void);
   pub fn shadowhook_dlsym(handle: *mut c_void, sym_name: *const c_char) -> *mut c_void;
   pub fn shadowhook_dlsym_dynsym(handle: *mut c_void, sym_name: *const c_char) -> *mut c_void;
   pub fn shadowhook_dlsym_symtab(handle: *mut c_void, sym_name: *const c_char) -> *mut c_void;

   pub fn shadowhook_register_dl_init_callback(
      pre: shadowhook_dl_info_t,
      post: shadowhook_dl_info_t,
      data: *mut c_void,
   ) -> c_int;
   pub fn shadowhook_unregister_dl_init_callback(
      pre: shadowhook_dl_info_t,
      post: shadowhook_dl_info_t,
      data: *mut c_void,
   ) -> c_int;
   pub fn shadowhook_register_dl_fini_callback(
      pre: shadowhook_dl_info_t,
      post: shadowhook_dl_info_t,
      data: *mut c_void,
   ) -> c_int;
   pub fn shadowhook_unregister_dl_fini_callback(
      pre: shadowhook_dl_info_t,
      post: shadowhook_dl_info_t,
      data: *mut c_void,
   ) -> c_int;

   pub fn shadowhook_get_prev_func(func: *mut c_void) -> *mut c_void;
   pub fn shadowhook_pop_stack(return_address: *mut c_void);
   pub fn shadowhook_allow_reentrant(return_address: *mut c_void);
   pub fn shadowhook_disallow_reentrant(return_address: *mut c_void);
   pub fn shadowhook_get_return_address() -> *mut c_void;

   pub fn shadowhook_pop_stack_by_func(func: *mut c_void);
   pub fn shadowhook_allow_reentrant_by_func(func: *mut c_void);
   pub fn shadowhook_disallow_reentrant_by_func(func: *mut c_void);
}
