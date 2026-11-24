use std::{
   ffi::{
      c_char,
      c_int,
      c_void,
   },
   ptr::NonNull,
};

use sunhook_sys::{
   SHADOWHOOK_INTERCEPT_DEFAULT,
   SHADOWHOOK_INTERCEPT_RECORD,
   SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_ONLY,
   SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_WRITE,
   SHADOWHOOK_INTERCEPT_WITH_FPSIMD_WRITE_ONLY,
   shadowhook_cpu_context_t,
   shadowhook_intercept_func_addr,
   shadowhook_intercept_instr_addr,
   shadowhook_intercept_sym_addr,
   shadowhook_intercept_sym_name,
   shadowhook_intercept_sym_name_callback,
   shadowhook_interceptor_t,
   shadowhook_unintercept,
   shadowhook_vreg_t,
};

use crate::{
   OnDone,
   RecordName,
   Stub,
   Target,
   call_on_done,
   error::Error,
   leak_on_done,
   record_ptrs,
};

/// The registers at the intercepted instruction. Writes are restored into the
/// CPU before the instruction runs.
pub type CpuContext = shadowhook_cpu_context_t;

pub type VReg = shadowhook_vreg_t;

/// Which floating point and SIMD registers [`CpuContext::vregs`] carries.
///
/// On x86_64 every variant behaves like [`Fpsimd::ReadWrite`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Fpsimd {
   /// `vregs` is neither filled nor written back, the cheapest option.
   #[default]
   Off,
   Read,
   Write,
   ReadWrite,
}

impl Fpsimd {
   const fn flag(self) -> u32 {
      match self {
         Self::Off => SHADOWHOOK_INTERCEPT_DEFAULT,
         Self::Read => SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_ONLY,
         Self::Write => SHADOWHOOK_INTERCEPT_WITH_FPSIMD_WRITE_ONLY,
         Self::ReadWrite => SHADOWHOOK_INTERCEPT_WITH_FPSIMD_READ_WRITE,
      }
   }
}

/// An installed intercept. Dropping it leaves the intercept in place.
///
/// The interceptor closure is never freed, because another thread may still be
/// running it when [`unintercept`](Self::unintercept) returns.
#[must_use = "dropping an Intercept leaves it installed, call unintercept() to remove it"]
pub struct Intercept {
   stub: Stub,
}

impl Intercept {
   /// Whether the target library was not loaded yet, so the intercept waits for
   /// the linker.
   #[must_use]
   pub const fn is_pending(&self) -> bool {
      self.stub.pending
   }

   pub fn unintercept(self) -> Result<(), Error> {
      self.stub.remove(shadowhook_unintercept)
   }
}

type AddrInterceptFn = unsafe extern "C" fn(
   *mut c_void,
   shadowhook_interceptor_t,
   *mut c_void,
   u32,
   ...
) -> *mut c_void;

/// Runs `interceptor` before the first instruction of the function at `target`.
///
/// # Safety
///
/// `target` must be the entry of a function. Registers written through the
/// context must leave the function in a state it can run from.
pub unsafe fn intercept<I>(
   target: Target<'_>,
   interceptor: I,
   fpsimd: Fpsimd,
) -> Result<Intercept, Error>
where
   I: Fn(&mut CpuContext) + Send + Sync + 'static,
{
   let (install, addr, record): (AddrInterceptFn, _, _) = match target {
      Target::FuncAddr { addr, record } => (shadowhook_intercept_func_addr, addr, record),
      Target::SymAddr { addr, record } => (shadowhook_intercept_sym_addr, addr, record),
      Target::SymName {
         lib,
         sym,
         on_done: None,
      } => {
         let data = Box::into_raw(Box::new(interceptor));
         let raw = unsafe {
            shadowhook_intercept_sym_name(
               lib.as_ptr(),
               sym.as_ptr(),
               Some(trampoline::<I>),
               data.cast(),
               fpsimd.flag(),
            )
         };
         return unsafe { finish(raw, data, None) };
      },
      Target::SymName {
         lib,
         sym,
         on_done: Some(on_done),
      } => {
         let data = Box::into_raw(Box::new(interceptor));
         let on_done = leak_on_done(on_done);
         let raw = unsafe {
            shadowhook_intercept_sym_name_callback(
               lib.as_ptr(),
               sym.as_ptr(),
               Some(trampoline::<I>),
               data.cast(),
               fpsimd.flag(),
               Some(on_intercepted),
               on_done.as_ptr().cast(),
            )
         };
         return unsafe { finish(raw, data, Some(on_done)) };
      },
   };

   unsafe { install_at(install, addr, record, interceptor, fpsimd) }
}

/// Runs `interceptor` before the instruction at `addr`, which may sit anywhere
/// in a function. On arm32 a Thumb instruction's address must have bit 0 set.
///
/// # Safety
///
/// `addr` must be the start of an instruction. Registers written through the
/// context must leave the function in a state it can run from.
pub unsafe fn intercept_instr<I>(
   addr: NonNull<c_void>,
   record: Option<RecordName<'_>>,
   interceptor: I,
   fpsimd: Fpsimd,
) -> Result<Intercept, Error>
where
   I: Fn(&mut CpuContext) + Send + Sync + 'static,
{
   unsafe {
      install_at(
         shadowhook_intercept_instr_addr,
         addr,
         record,
         interceptor,
         fpsimd,
      )
   }
}

unsafe fn install_at<I>(
   install: AddrInterceptFn,
   addr: NonNull<c_void>,
   record: Option<RecordName<'_>>,
   interceptor: I,
   fpsimd: Fpsimd,
) -> Result<Intercept, Error>
where
   I: Fn(&mut CpuContext) + Send + Sync + 'static,
{
   let data = Box::into_raw(Box::new(interceptor));
   let flags = if record.is_some() {
      fpsimd.flag() | SHADOWHOOK_INTERCEPT_RECORD
   } else {
      fpsimd.flag()
   };
   let (record_lib, record_sym) = record_ptrs(record);
   let raw = unsafe {
      install(
         addr.as_ptr(),
         Some(trampoline::<I>),
         data.cast(),
         flags,
         record_lib,
         record_sym,
      )
   };
   unsafe { finish(raw, data, None) }
}

unsafe fn finish<I>(
   raw: *mut c_void,
   data: *mut I,
   on_done: Option<NonNull<OnDone>>,
) -> Result<Intercept, Error> {
   let stub = Stub::new(raw, on_done).inspect_err(|_| drop(unsafe { Box::from_raw(data) }))?;
   Ok(Intercept { stub })
}

unsafe extern "C" fn trampoline<I: Fn(&mut CpuContext)>(
   context: *mut CpuContext,
   data: *mut c_void,
) {
   let interceptor = unsafe { &*data.cast::<I>() };
   interceptor(unsafe { &mut *context });
}

unsafe extern "C" fn on_intercepted(
   errno: c_int,
   _lib: *const c_char,
   _sym: *const c_char,
   sym_addr: *mut c_void,
   _pre: shadowhook_interceptor_t,
   _data: *mut c_void,
   arg: *mut c_void,
) {
   unsafe { call_on_done(arg, errno, sym_addr) }
}
