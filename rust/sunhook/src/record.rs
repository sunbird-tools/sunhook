use std::{
   ffi::CStr,
   ops::{
      BitOr,
      BitOrAssign,
   },
   os::fd::{
      AsRawFd,
      BorrowedFd,
   },
};

use sunhook_sys::{
   SHADOWHOOK_RECORD_ITEM_ALL,
   SHADOWHOOK_RECORD_ITEM_BACKUP_LEN,
   SHADOWHOOK_RECORD_ITEM_CALLER_LIB_NAME,
   SHADOWHOOK_RECORD_ITEM_ERRNO,
   SHADOWHOOK_RECORD_ITEM_FLAGS,
   SHADOWHOOK_RECORD_ITEM_LIB_NAME,
   SHADOWHOOK_RECORD_ITEM_NEW_ADDR,
   SHADOWHOOK_RECORD_ITEM_OP,
   SHADOWHOOK_RECORD_ITEM_STUB,
   SHADOWHOOK_RECORD_ITEM_SYM_ADDR,
   SHADOWHOOK_RECORD_ITEM_SYM_NAME,
   SHADOWHOOK_RECORD_ITEM_TIMESTAMP,
   SHADOWHOOK_RECORD_ITEM_TRACE,
   shadowhook_dump_records,
   shadowhook_get_records,
};

/// The columns of each operation record, combined with `|`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Items(u32);

impl Items {
   pub const ALL: Self = Self(SHADOWHOOK_RECORD_ITEM_ALL);
   pub const BACKUP_LEN: Self = Self(SHADOWHOOK_RECORD_ITEM_BACKUP_LEN);
   pub const CALLER_LIB_NAME: Self = Self(SHADOWHOOK_RECORD_ITEM_CALLER_LIB_NAME);
   pub const ERRNO: Self = Self(SHADOWHOOK_RECORD_ITEM_ERRNO);
   pub const FLAGS: Self = Self(SHADOWHOOK_RECORD_ITEM_FLAGS);
   pub const LIB_NAME: Self = Self(SHADOWHOOK_RECORD_ITEM_LIB_NAME);
   pub const NEW_ADDR: Self = Self(SHADOWHOOK_RECORD_ITEM_NEW_ADDR);
   pub const OP: Self = Self(SHADOWHOOK_RECORD_ITEM_OP);
   pub const STUB: Self = Self(SHADOWHOOK_RECORD_ITEM_STUB);
   pub const SYM_ADDR: Self = Self(SHADOWHOOK_RECORD_ITEM_SYM_ADDR);
   pub const SYM_NAME: Self = Self(SHADOWHOOK_RECORD_ITEM_SYM_NAME);
   pub const TIMESTAMP: Self = Self(SHADOWHOOK_RECORD_ITEM_TIMESTAMP);
   pub const TRACE: Self = Self(SHADOWHOOK_RECORD_ITEM_TRACE);
}

impl BitOr for Items {
   type Output = Self;

   fn bitor(self, rhs: Self) -> Self {
      Self(self.0 | rhs.0)
   }
}

impl BitOrAssign for Items {
   fn bitor_assign(&mut self, rhs: Self) {
      self.0 |= rhs.0;
   }
}

/// The operation log as CSV lines, or `None` while [`set_recordable`](crate::set_recordable) is
/// off.
#[must_use]
pub fn records(items: Items) -> Option<String> {
   let raw = unsafe { shadowhook_get_records(items.0) };
   if raw.is_null() {
      return None;
   }

   let text = unsafe { CStr::from_ptr(raw) }
      .to_string_lossy()
      .into_owned();
   unsafe { libc::free(raw.cast()) };
   Some(text)
}

/// Writes the operation log to `fd`. Async-signal-safe, so it works from a
/// crash handler.
pub fn dump(fd: BorrowedFd<'_>, items: Items) {
   unsafe { shadowhook_dump_records(fd.as_raw_fd(), items.0) }
}
