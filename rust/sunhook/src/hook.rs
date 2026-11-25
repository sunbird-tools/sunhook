use std::{
   ffi::{
      c_char,
      c_int,
      c_void,
   },
   marker::PhantomData,
   mem,
   ptr::{
      self,
      NonNull,
   },
   sync::atomic::{
      AtomicPtr,
      Ordering,
   },
};

use sunhook_sys::{
   SHADOWHOOK_HOOK_DEFAULT,
   SHADOWHOOK_HOOK_RECORD,
   shadowhook_allow_reentrant_by_func,
   shadowhook_disallow_reentrant_by_func,
   shadowhook_get_prev_func,
   shadowhook_get_return_address,
   shadowhook_hook_func_addr_2,
   shadowhook_hook_sym_addr_2,
   shadowhook_hook_sym_name_2,
   shadowhook_hook_sym_name_callback_2,
   shadowhook_pop_stack_by_func,
   shadowhook_unhook,
};

use crate::{
   Mode,
   Stub,
   Target,
   call_on_done,
   error::Error,
   leak_on_done,
   record_ptrs,
};

mod sealed {
   pub trait Sealed {}
}

/// An `extern "C"` function pointer type of up to 12 arguments, safe or
/// `unsafe`.
///
/// # Safety
///
/// `from_addr(f.addr())` must give back `f`. Only this crate implements it.
pub unsafe trait FnPtr: Copy + sealed::Sealed + 'static {
   fn addr(self) -> *mut c_void;

   /// # Safety
   ///
   /// `addr` must be the entry of a function with exactly this signature.
   unsafe fn from_addr(addr: NonNull<c_void>) -> Self;
}

macro_rules! fn_ptr {
   ($($arg:ident),*) => {
      fn_ptr!(@impl extern "C" fn($($arg),*) -> Ret; $($arg),*);
      fn_ptr!(@impl unsafe extern "C" fn($($arg),*) -> Ret; $($arg),*);
   };
   (@impl $ty:ty; $($arg:ident),*) => {
      impl<Ret: 'static, $($arg: 'static),*> sealed::Sealed for $ty {}

      unsafe impl<Ret: 'static, $($arg: 'static),*> FnPtr for $ty {
         fn addr(self) -> *mut c_void {
            self as *mut c_void
         }

         unsafe fn from_addr(addr: NonNull<c_void>) -> Self {
            unsafe { mem::transmute::<*mut c_void, Self>(addr.as_ptr()) }
         }
      }
   };
}

fn_ptr!();
fn_ptr!(A1);
fn_ptr!(A1, A2);
fn_ptr!(A1, A2, A3);
fn_ptr!(A1, A2, A3, A4);
fn_ptr!(A1, A2, A3, A4, A5);
fn_ptr!(A1, A2, A3, A4, A5, A6);
fn_ptr!(A1, A2, A3, A4, A5, A6, A7);
fn_ptr!(A1, A2, A3, A4, A5, A6, A7, A8);
fn_ptr!(A1, A2, A3, A4, A5, A6, A7, A8, A9);
fn_ptr!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10);
fn_ptr!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11);
fn_ptr!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12);

/// The address a proxy calls to reach the original function, written by
/// shadowhook.
///
/// In multi mode shadowhook rewrites it from other threads whenever a
/// neighbouring proxy is removed, which is why it has to be a `static` and
/// stays valid after unhook.
#[repr(transparent)]
pub struct Orig<F> {
   addr:   AtomicPtr<c_void>,
   marker: PhantomData<F>,
}

impl<F: FnPtr> Orig<F> {
   #[must_use]
   pub const fn new() -> Self {
      Self {
         addr:   AtomicPtr::new(ptr::null_mut()),
         marker: PhantomData,
      }
   }

   /// Panics before the hook that owns this slot has been installed.
   pub fn get(&self) -> F {
      let addr = NonNull::new(self.addr.load(Ordering::Acquire))
         .expect("Orig::get called before its hook was installed");
      // SAFETY: shadowhook only stores the original function or the next proxy
      // here, and the caller of hook() promised both have signature F.
      unsafe { F::from_addr(addr) }
   }

   const fn as_raw(&'static self) -> *mut *mut c_void {
      self.addr.as_ptr()
   }
}

impl<F: FnPtr> Default for Orig<F> {
   fn default() -> Self {
      Self::new()
   }
}

/// An installed hook. Dropping it leaves the hook in place.
#[must_use = "dropping a Hook leaves it installed, call unhook() to remove it"]
pub struct Hook {
   stub: Stub,
}

impl Hook {
   /// Whether the target library was not loaded yet, so the hook waits for the
   /// linker. Always false on Linux, where an unloaded library fails with
   /// [`Error::NotFound`].
   #[must_use]
   pub const fn is_pending(&self) -> bool {
      self.stub.pending
   }

   pub fn unhook(self) -> Result<(), Error> {
      self.stub.remove(shadowhook_unhook)
   }
}

type AddrHookFn =
   unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void, u32, ...) -> *mut c_void;

/// Replaces the function at `target` with `proxy`.
///
/// `mode` of `None` uses the mode given to [`init`](crate::init). `orig` is required in multi
/// mode and unused in shared mode, where [`StackScope::prev`] reaches the
/// original.
///
/// # Safety
///
/// - `target` must be the entry of a function whose calling convention,
///   arguments and return value match `F`.
/// - In shared mode `proxy` must hold a [`StackScope`] for every call.
pub unsafe fn hook<F: FnPtr>(
   target: Target<'_>,
   proxy: F,
   orig: Option<&'static Orig<F>>,
   mode: Option<Mode>,
) -> Result<Hook, Error> {
   let new_addr = proxy.addr();
   let orig_addr = orig.map_or(ptr::null_mut(), Orig::as_raw);
   let flags = mode.map_or(SHADOWHOOK_HOOK_DEFAULT, Mode::hook_flag);

   let (install, addr, record): (AddrHookFn, _, _) = match target {
      Target::FuncAddr { addr, record } => (shadowhook_hook_func_addr_2, addr, record),
      Target::SymAddr { addr, record } => (shadowhook_hook_sym_addr_2, addr, record),
      Target::SymName {
         lib,
         sym,
         on_done: None,
      } => {
         let raw = unsafe {
            shadowhook_hook_sym_name_2(lib.as_ptr(), sym.as_ptr(), new_addr, orig_addr, flags)
         };
         return Ok(Hook {
            stub: Stub::new(raw, None)?,
         });
      },
      Target::SymName {
         lib,
         sym,
         on_done: Some(on_done),
      } => {
         let on_done = leak_on_done(on_done);
         let raw = unsafe {
            shadowhook_hook_sym_name_callback_2(
               lib.as_ptr(),
               sym.as_ptr(),
               new_addr,
               orig_addr,
               flags,
               Some(on_hooked),
               on_done.as_ptr().cast(),
            )
         };
         return Ok(Hook {
            stub: Stub::new(raw, Some(on_done))?,
         });
      },
   };

   let flags = if record.is_some() {
      flags | SHADOWHOOK_HOOK_RECORD
   } else {
      flags
   };
   let (record_lib, record_sym) = record_ptrs(record);
   let raw = unsafe {
      install(
         addr.as_ptr(),
         new_addr,
         orig_addr,
         flags,
         record_lib,
         record_sym,
      )
   };
   Ok(Hook {
      stub: Stub::new(raw, None)?,
   })
}

unsafe extern "C" fn on_hooked(
   errno: c_int,
   _lib: *const c_char,
   _sym: *const c_char,
   sym_addr: *mut c_void,
   _new_addr: *mut c_void,
   _orig_addr: *mut c_void,
   arg: *mut c_void,
) {
   unsafe { call_on_done(arg, errno, sym_addr) }
}

/// Bookkeeping for one call of a shared mode proxy, released when dropped.
///
/// shadowhook pushes a frame per call to detect recursion between proxies, and
/// this guard pops it on every return path. It plays the role of
/// `SHADOWHOOK_STACK_SCOPE` in C++.
pub struct StackScope<F: FnPtr> {
   proxy:  F,
   thread: PhantomData<*const ()>,
}

impl<F: FnPtr> StackScope<F> {
   /// # Safety
   ///
   /// Call once per invocation, inside a proxy installed in shared mode, and
   /// keep the guard until the proxy returns. `proxy` must be that proxy, as
   /// the same `F` passed to [`hook`].
   pub const unsafe fn enter(proxy: F) -> Self {
      Self {
         proxy,
         thread: PhantomData,
      }
   }

   /// The next proxy in the chain, or the original function after the last one.
   pub fn prev(&self) -> F {
      let addr = NonNull::new(unsafe { shadowhook_get_prev_func(self.proxy.addr()) })
         .expect("shadowhook_get_prev_func returned null");
      // SAFETY: every proxy on this hub and the original share the signature F,
      // per enter().
      unsafe { F::from_addr(addr) }
   }

   /// Lets this proxy run again if the hooked function recurses before this
   /// call returns.
   pub fn allow_reentrant(&self) {
      unsafe { shadowhook_allow_reentrant_by_func(self.proxy.addr()) }
   }

   pub fn disallow_reentrant(&self) {
      unsafe { shadowhook_disallow_reentrant_by_func(self.proxy.addr()) }
   }

   /// The caller's return address. The hub's trampoline replaces LR, so this is
   /// the only way to get it inside the proxy.
   pub fn return_address(&self) -> *mut c_void {
      unsafe { shadowhook_get_return_address() }
   }
}

impl<F: FnPtr> Drop for StackScope<F> {
   fn drop(&mut self) {
      unsafe { shadowhook_pop_stack_by_func(self.proxy.addr()) }
   }
}
