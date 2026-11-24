//! Safe bindings to sunhook, a fork of the shadowhook Android inline hook
//! library.
//!
//! - [`init`] must succeed before anything else is installed.
//! - [`hook::hook`] replaces a whole function with a proxy. [`hook::Orig`]
//!   holds the address used to reach the original in unique and multi mode.
//!   [`hook::StackScope`] does the per-call bookkeeping that shared mode
//!   requires.
//! - [`intercept::intercept`] runs a closure with the CPU registers before an
//!   instruction.
//! - [`linker`] resolves symbols past linker namespaces and observes ELF
//!   constructors and destructors.
//! - [`record`] exports the operation log.
//!
//! `libshadowhook_nothing.so` is built next to the final artifact. `init`
//! dlopen()s it by basename, so it has to be packaged in the APK alongside the
//! library that links sunhook.
//!
//! ```no_run
//! use std::ffi::c_void;
//!
//! use sunhook::{
//!    Mode,
//!    Target,
//!    hook::{
//!       self,
//!       StackScope,
//!    },
//! };
//!
//! type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
//!
//! unsafe extern "C" fn malloc_proxy(size: usize) -> *mut c_void {
//!    let scope = unsafe { StackScope::enter(malloc_proxy as Malloc) };
//!    unsafe { scope.prev()(size) }
//! }
//!
//! sunhook::init(Mode::Shared, false)?;
//! let hook = unsafe {
//!    hook::hook(
//!       Target::name(c"libc.so", c"malloc"),
//!       malloc_proxy as Malloc,
//!       None,
//!       None,
//!    )?
//! };
//! hook.unhook()?;
//! # Ok::<(), sunhook::error::Error>(())
//! ```

pub mod error;
pub mod hook;
pub mod intercept;
pub mod linker;
pub mod record;

use std::{
   ffi::{
      CStr,
      c_char,
      c_int,
      c_void,
   },
   ptr::NonNull,
};

use sunhook_sys::{
   SHADOWHOOK_ERRNO_PENDING,
   SHADOWHOOK_HOOK_WITH_MULTI_MODE,
   SHADOWHOOK_HOOK_WITH_SHARED_MODE,
   SHADOWHOOK_HOOK_WITH_UNIQUE_MODE,
   SHADOWHOOK_MODE_MULTI,
   SHADOWHOOK_MODE_SHARED,
   SHADOWHOOK_MODE_UNIQUE,
   shadowhook_get_debuggable,
   shadowhook_get_disable,
   shadowhook_get_errno,
   shadowhook_get_init_errno,
   shadowhook_get_mode,
   shadowhook_get_recordable,
   shadowhook_get_version,
   shadowhook_init,
   shadowhook_mode_t,
   shadowhook_set_debuggable,
   shadowhook_set_disable,
   shadowhook_set_recordable,
};

use crate::error::Error;

/// How proxies installed on the same address coexist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
   /// Many proxies per address. The hub breaks recursion between proxies, and
   /// every proxy must hold a [`hook::StackScope`] for the duration of its
   /// call.
   Shared,
   /// One proxy per address. Calls the original through [`hook::Orig`].
   Unique,
   /// Many proxies per address chained through each one's [`hook::Orig`]. No
   /// recursion guard.
   Multi,
}

impl Mode {
   const fn to_raw(self) -> shadowhook_mode_t {
      match self {
         Self::Shared => SHADOWHOOK_MODE_SHARED,
         Self::Unique => SHADOWHOOK_MODE_UNIQUE,
         Self::Multi => SHADOWHOOK_MODE_MULTI,
      }
   }

   const fn hook_flag(self) -> u32 {
      match self {
         Self::Shared => SHADOWHOOK_HOOK_WITH_SHARED_MODE,
         Self::Unique => SHADOWHOOK_HOOK_WITH_UNIQUE_MODE,
         Self::Multi => SHADOWHOOK_HOOK_WITH_MULTI_MODE,
      }
   }
}

/// Initializes shadowhook. `mode` is used by hooks installed without an
/// explicit mode and cannot be changed later.
pub fn init(mode: Mode, debuggable: bool) -> Result<(), Error> {
   Error::check(unsafe { shadowhook_init(mode.to_raw(), debuggable) })
}

/// The outcome of the first [`init`] call, or [`Error::Uninit`] before one.
pub fn init_status() -> Result<(), Error> {
   Error::check(unsafe { shadowhook_get_init_errno() })
}

#[must_use]
pub fn version() -> &'static str {
   unsafe { CStr::from_ptr(shadowhook_get_version()) }
      .to_str()
      .expect("SHADOWHOOK_VERSION is ASCII")
}

/// The default mode passed to [`init`].
#[must_use]
pub fn mode() -> Mode {
   match unsafe { shadowhook_get_mode() } {
      SHADOWHOOK_MODE_SHARED => Mode::Shared,
      SHADOWHOOK_MODE_UNIQUE => Mode::Unique,
      SHADOWHOOK_MODE_MULTI => Mode::Multi,
      other => unreachable!("shadowhook_get_mode returned {other}"),
   }
}

#[must_use]
pub fn debuggable() -> bool {
   unsafe { shadowhook_get_debuggable() }
}

/// Toggles logging to logcat.
pub fn set_debuggable(debuggable: bool) {
   unsafe { shadowhook_set_debuggable(debuggable) }
}

#[must_use]
pub fn recordable() -> bool {
   unsafe { shadowhook_get_recordable() }
}

/// Toggles the operation log read by [`record::records`].
pub fn set_recordable(recordable: bool) {
   unsafe { shadowhook_set_recordable(recordable) }
}

#[must_use]
pub fn disabled() -> bool {
   unsafe { shadowhook_get_disable() }
}

/// While disabled, every hook, intercept and unhook fails with
/// [`Error::Disabled`]. Installed hooks keep running.
pub fn set_disabled(disabled: bool) {
   unsafe { shadowhook_set_disable(disabled) }
}

/// Names written to the operation log for targets given by address.
#[derive(Clone, Copy, Debug)]
pub struct RecordName<'a> {
   pub lib: &'a CStr,
   pub sym: &'a CStr,
}

/// Called each time a deferred [`Target::SymName`] operation runs, which
/// happens again whenever the library is unloaded and reloaded. Receives the
/// resolved symbol address.
pub type OnDone = Box<dyn FnMut(Result<NonNull<c_void>, Error>) + Send>;

/// Where a hook or intercept is installed.
pub enum Target<'a> {
   /// The first instruction of a function, which needs no symbol.
   FuncAddr {
      addr:   NonNull<c_void>,
      record: Option<RecordName<'a>>,
   },
   /// The first instruction of a function that has an entry in `.dynsym` or
   /// `.symtab`. shadowhook reads the symbol size to rewrite short functions
   /// safely.
   SymAddr {
      addr:   NonNull<c_void>,
      record: Option<RecordName<'a>>,
   },
   /// A symbol looked up by library basename or pathname. When the library is
   /// not loaded yet the operation is deferred until the linker loads it, and
   /// `on_done` reports the result.
   SymName {
      lib:     &'a CStr,
      sym:     &'a CStr,
      on_done: Option<OnDone>,
   },
}

impl<'a> Target<'a> {
   #[must_use]
   pub const fn func(addr: NonNull<c_void>) -> Self {
      Self::FuncAddr { addr, record: None }
   }

   #[must_use]
   pub const fn sym(addr: NonNull<c_void>) -> Self {
      Self::SymAddr { addr, record: None }
   }

   #[must_use]
   pub const fn name(lib: &'a CStr, sym: &'a CStr) -> Self {
      Self::SymName {
         lib,
         sym,
         on_done: None,
      }
   }
}

/// The handle a hook or intercept call returned, whether the call was deferred,
/// and the `on_done` box shadowhook holds a pointer to.
struct Stub {
   ptr:     NonNull<c_void>,
   pending: bool,
   on_done: Option<NonNull<OnDone>>,
}

// SAFETY: shadowhook accepts the handle from any thread, OnDone is Send, and
// only remove(self) touches the box again.
unsafe impl Send for Stub {}
unsafe impl Sync for Stub {}

impl Stub {
   /// Frees `on_done` when the call failed, since shadowhook then never calls
   /// it.
   fn new(ptr: *mut c_void, on_done: Option<NonNull<OnDone>>) -> Result<Self, Error> {
      let errno = unsafe { shadowhook_get_errno() };
      let Some(ptr) = NonNull::new(ptr) else {
         if let Some(on_done) = on_done {
            drop(unsafe { Box::from_raw(on_done.as_ptr()) });
         }
         return Err(Error::from_errno(errno));
      };

      Ok(Self {
         ptr,
         pending: errno == SHADOWHOOK_ERRNO_PENDING,
         on_done,
      })
   }

   /// Keeps `on_done` allocated on failure, since shadowhook may still call it.
   fn remove(self, unop: unsafe extern "C" fn(*mut c_void) -> c_int) -> Result<(), Error> {
      if unsafe { unop(self.ptr.as_ptr()) } != 0 {
         return Err(Error::last());
      }

      if let Some(on_done) = self.on_done {
         drop(unsafe { Box::from_raw(on_done.as_ptr()) });
      }

      Ok(())
   }
}

fn leak_on_done(on_done: OnDone) -> NonNull<OnDone> {
   NonNull::from(Box::leak(Box::new(on_done)))
}

fn on_done_result(errno: c_int, sym_addr: *mut c_void) -> Result<NonNull<c_void>, Error> {
   Error::check(errno)?;
   Ok(NonNull::new(sym_addr).expect("shadowhook reported success for a null symbol"))
}

unsafe fn call_on_done(arg: *mut c_void, errno: c_int, sym_addr: *mut c_void) {
   // SAFETY: arg is the Box<OnDone> leaked at install time. shadowhook runs a
   // task's callback under the task's lock, so calls never overlap, and unhook
   // takes the same lock before the box is freed.
   let on_done = unsafe { &mut *arg.cast::<OnDone>() };
   on_done(on_done_result(errno, sym_addr));
}

fn record_ptrs(record: Option<RecordName<'_>>) -> (*const c_char, *const c_char) {
   record.map_or((std::ptr::null(), std::ptr::null()), |name| {
      (name.lib.as_ptr(), name.sym.as_ptr())
   })
}
