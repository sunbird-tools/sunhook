#[cfg(not(target_vendor = "apple"))] use std::ffi::c_int;
use std::{
   ffi::{
      CStr,
      c_char,
      c_void,
   },
   marker::PhantomData,
   ptr::NonNull,
};

#[cfg(not(target_vendor = "apple"))]
use libc::{
   dl_phdr_info,
   size_t,
};
#[cfg(not(target_vendor = "apple"))]
use sunhook_sys::{
   shadowhook_dl_info_t,
   shadowhook_register_dl_fini_callback,
   shadowhook_register_dl_init_callback,
   shadowhook_unregister_dl_fini_callback,
   shadowhook_unregister_dl_init_callback,
};
use sunhook_sys::{
   shadowhook_dlclose,
   shadowhook_dlopen,
   shadowhook_dlsym,
   shadowhook_dlsym_dynsym,
   shadowhook_dlsym_symtab,
};

#[cfg(not(target_vendor = "apple"))]
use crate::error::Error;

/// An ELF already loaded in the process, found past linker namespace
/// restrictions.
pub struct Library {
   handle: NonNull<c_void>,
   // xdl loads .symtab lazily on first lookup, so lookups mutate the handle.
   unsync: PhantomData<*const ()>,
}

// SAFETY: the handle is heap state owned by this value with no thread affinity.
unsafe impl Send for Library {}

impl Library {
   /// Finds a loaded ELF by basename or pathname. Never loads one.
   #[must_use]
   pub fn open(name: &CStr) -> Option<Self> {
      let handle = NonNull::new(unsafe { shadowhook_dlopen(name.as_ptr()) })?;
      Some(Self {
         handle,
         unsync: PhantomData,
      })
   }

   /// Looks the symbol up in `.dynsym`, then `.symtab`.
   pub fn sym(&self, name: &CStr) -> Option<NonNull<c_void>> {
      self.lookup(shadowhook_dlsym, name)
   }

   pub fn dynsym(&self, name: &CStr) -> Option<NonNull<c_void>> {
      self.lookup(shadowhook_dlsym_dynsym, name)
   }

   /// Reads `.symtab`, including the copy compressed into `.gnu_debugdata`.
   pub fn symtab(&self, name: &CStr) -> Option<NonNull<c_void>> {
      self.lookup(shadowhook_dlsym_symtab, name)
   }

   fn lookup(
      &self,
      find: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
      name: &CStr,
   ) -> Option<NonNull<c_void>> {
      NonNull::new(unsafe { find(self.handle.as_ptr(), name.as_ptr()) })
   }
}

impl Drop for Library {
   fn drop(&mut self) {
      unsafe { shadowhook_dlclose(self.handle.as_ptr()) }
   }
}

/// Which side of the linker's call into `.init`/`.init_array` or
/// `.fini`/`.fini_array`.
#[cfg(not(target_vendor = "apple"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Phase {
   Pre,
   Post,
}

#[cfg(not(target_vendor = "apple"))]
type Callback = Box<dyn Fn(Phase, &dl_phdr_info) + Send + Sync>;
#[cfg(not(target_vendor = "apple"))]
type UnregisterFn =
   unsafe extern "C" fn(shadowhook_dl_info_t, shadowhook_dl_info_t, *mut c_void) -> c_int;

/// A registered linker callback. Dropping it leaves the callback registered.
#[cfg(not(target_vendor = "apple"))]
#[must_use = "dropping a DlCallback leaves it registered, call unregister() to remove it"]
pub struct DlCallback {
   data:       NonNull<Callback>,
   unregister: UnregisterFn,
}

// SAFETY: the callback is Send + Sync, and only unregister(self) frees it.
#[cfg(not(target_vendor = "apple"))]
unsafe impl Send for DlCallback {}
#[cfg(not(target_vendor = "apple"))]
unsafe impl Sync for DlCallback {}

#[cfg(not(target_vendor = "apple"))]
impl DlCallback {
   /// Runs `callback` around every ELF's constructors. Requires Android 5.0 on
   /// arm32, and fails with [`Error::NotSupported`] on Linux.
   ///
   /// The linker holds a lock shared with [`unregister`](Self::unregister) while it runs
   /// callbacks, so unregistering from inside one deadlocks.
   pub fn on_init<F>(callback: F) -> Result<Self, Error>
   where
      F: Fn(Phase, &dl_phdr_info) + Send + Sync + 'static,
   {
      Self::register(
         Box::new(callback),
         shadowhook_register_dl_init_callback,
         shadowhook_unregister_dl_init_callback,
      )
   }

   /// Runs `callback` around every ELF's destructors. Requires Android 5.0 on
   /// arm32, and fails with [`Error::NotSupported`] on Linux.
   ///
   /// The linker holds a lock shared with [`unregister`](Self::unregister) while it runs
   /// callbacks, so unregistering from inside one deadlocks.
   pub fn on_fini<F>(callback: F) -> Result<Self, Error>
   where
      F: Fn(Phase, &dl_phdr_info) + Send + Sync + 'static,
   {
      Self::register(
         Box::new(callback),
         shadowhook_register_dl_fini_callback,
         shadowhook_unregister_dl_fini_callback,
      )
   }

   fn register(
      callback: Callback,
      register: UnregisterFn,
      unregister: UnregisterFn,
   ) -> Result<Self, Error> {
      let data = NonNull::from(Box::leak(Box::new(callback)));
      if unsafe { register(Some(pre), Some(post), data.as_ptr().cast()) } != 0 {
         drop(unsafe { Box::from_raw(data.as_ptr()) });
         return Err(Error::last());
      }

      Ok(Self { data, unregister })
   }

   /// After success no call is in flight. On failure the callback stays
   /// registered and allocated.
   pub fn unregister(self) -> Result<(), Error> {
      if unsafe { (self.unregister)(Some(pre), Some(post), self.data.as_ptr().cast()) } != 0 {
         return Err(Error::last());
      }

      drop(unsafe { Box::from_raw(self.data.as_ptr()) });
      Ok(())
   }
}

#[cfg(not(target_vendor = "apple"))]
unsafe fn dispatch(phase: Phase, info: *mut dl_phdr_info, data: *mut c_void) {
   let callback = unsafe { &*data.cast::<Callback>() };
   callback(phase, unsafe { &*info });
}

#[cfg(not(target_vendor = "apple"))]
unsafe extern "C" fn pre(info: *mut dl_phdr_info, _size: size_t, data: *mut c_void) {
   unsafe { dispatch(Phase::Pre, info, data) }
}

#[cfg(not(target_vendor = "apple"))]
unsafe extern "C" fn post(info: *mut dl_phdr_info, _size: size_t, data: *mut c_void) {
   unsafe { dispatch(Phase::Post, info, data) }
}
