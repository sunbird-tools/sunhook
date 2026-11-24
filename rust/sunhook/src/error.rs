use std::{
   ffi::{
      CStr,
      c_int,
   },
   fmt,
};

use sunhook_sys::{
   SHADOWHOOK_ERRNO_OK,
   shadowhook_get_errno,
   shadowhook_to_errmsg,
};

macro_rules! errors {
   ($($variant:ident = $errno:ident,)*) => {
      /// A shadowhook error number. [`Display`](fmt::Display) prints shadowhook's own message.
      #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
      #[non_exhaustive]
      pub enum Error {
         $($variant,)*
      }

      impl Error {
         pub const fn errno(self) -> c_int {
            match self {
               $(Self::$variant => sunhook_sys::$errno,)*
            }
         }

         /// Panics on `OK`, `PENDING` and numbers shadowhook does not define, since this crate
         /// compiles the C library it binds and no such value reaches an error path.
         pub(crate) fn from_errno(errno: c_int) -> Self {
            match errno {
               $(sunhook_sys::$errno => Self::$variant,)*
               other => unreachable!("shadowhook error number {other} is not an error"),
            }
         }
      }
   };
}

errors! {
   Uninit = SHADOWHOOK_ERRNO_UNINIT,
   InvalidArg = SHADOWHOOK_ERRNO_INVALID_ARG,
   Oom = SHADOWHOOK_ERRNO_OOM,
   Mprotect = SHADOWHOOK_ERRNO_MPROT,
   WriteCrash = SHADOWHOOK_ERRNO_WRITE_CRASH,
   InitErrno = SHADOWHOOK_ERRNO_INIT_ERRNO,
   InitSigsegv = SHADOWHOOK_ERRNO_INIT_SIGSEGV,
   InitSigbus = SHADOWHOOK_ERRNO_INIT_SIGBUS,
   InterceptDup = SHADOWHOOK_ERRNO_INTERCEPT_DUP,
   InitSafe = SHADOWHOOK_ERRNO_INIT_SAFE,
   InitLinker = SHADOWHOOK_ERRNO_INIT_LINKER,
   InitHub = SHADOWHOOK_ERRNO_INIT_HUB,
   HubCreate = SHADOWHOOK_ERRNO_HUB_CREAT,
   MonitorDlopen = SHADOWHOOK_ERRNO_MONITOR_DLOPEN,
   HookUniqueDup = SHADOWHOOK_ERRNO_HOOK_UNIQUE_DUP,
   HookDlopenCrash = SHADOWHOOK_ERRNO_HOOK_DLOPEN_CRASH,
   HookDlsym = SHADOWHOOK_ERRNO_HOOK_DLSYM,
   HookDlsymCrash = SHADOWHOOK_ERRNO_HOOK_DLSYM_CRASH,
   HookDup = SHADOWHOOK_ERRNO_HOOK_DUP,
   HookDladdrCrash = SHADOWHOOK_ERRNO_HOOK_DLADDR_CRASH,
   HookDlinfo = SHADOWHOOK_ERRNO_HOOK_DLINFO,
   HookSymSize = SHADOWHOOK_ERRNO_HOOK_SYMSZ,
   HookEnter = SHADOWHOOK_ERRNO_HOOK_ENTER,
   HookRewriteCrash = SHADOWHOOK_ERRNO_HOOK_REWRITE_CRASH,
   HookRewriteFailed = SHADOWHOOK_ERRNO_HOOK_REWRITE_FAILED,
   UnhookNotFound = SHADOWHOOK_ERRNO_UNHOOK_NOTFOUND,
   UnhookCmpCrash = SHADOWHOOK_ERRNO_UNHOOK_CMP_CRASH,
   UnhookTrampoMismatch = SHADOWHOOK_ERRNO_UNHOOK_TRAMPO_MISMATCH,
   UnhookExitMismatch = SHADOWHOOK_ERRNO_UNHOOK_EXIT_MISMATCH,
   UnhookExitCrash = SHADOWHOOK_ERRNO_UNHOOK_EXIT_CRASH,
   UnhookOnError = SHADOWHOOK_ERRNO_UNHOOK_ON_ERROR,
   UnhookOnUnfinished = SHADOWHOOK_ERRNO_UNHOOK_ON_UNFINISHED,
   ElfArchMismatch = SHADOWHOOK_ERRNO_ELF_ARCH_MISMATCH,
   LinkerArchMismatch = SHADOWHOOK_ERRNO_LINKER_ARCH_MISMATCH,
   Dup = SHADOWHOOK_ERRNO_DUP,
   NotFound = SHADOWHOOK_ERRNO_NOT_FOUND,
   NotSupported = SHADOWHOOK_ERRNO_NOT_SUPPORT,
   InitTask = SHADOWHOOK_ERRNO_INIT_TASK,
   HookIslandExit = SHADOWHOOK_ERRNO_HOOK_ISLAND_EXIT,
   HookIslandEnter = SHADOWHOOK_ERRNO_HOOK_ISLAND_ENTER,
   HookIslandRewrite = SHADOWHOOK_ERRNO_HOOK_ISLAND_REWRITE,
   ModeConflict = SHADOWHOOK_ERRNO_MODE_CONFLICT,
   HookMultiDup = SHADOWHOOK_ERRNO_HOOK_MULTI_DUP,
   Disabled = SHADOWHOOK_ERRNO_DISABLED,
}

impl Error {
   pub(crate) fn check(errno: c_int) -> Result<(), Self> {
      if errno == SHADOWHOOK_ERRNO_OK {
         return Ok(());
      }

      Err(Self::from_errno(errno))
   }

   /// The error number shadowhook stored for the calling thread's last failed
   /// call.
   pub(crate) fn last() -> Self {
      Self::from_errno(unsafe { shadowhook_get_errno() })
   }
}

impl fmt::Display for Error {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      let message = unsafe { CStr::from_ptr(shadowhook_to_errmsg(self.errno())) };
      f.write_str(&message.to_string_lossy())
   }
}

impl std::error::Error for Error {}
