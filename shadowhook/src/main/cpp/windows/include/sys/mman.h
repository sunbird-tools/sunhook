// mmap, munmap and mprotect over VirtualAlloc, VirtualFree and VirtualProtect, enough for the
// anonymous executable mappings and code patching shadowhook does.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <windows.h>

#define PROT_NONE  0
#define PROT_READ  1
#define PROT_WRITE 2
#define PROT_EXEC  4

#define MAP_PRIVATE   0x02
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_ANON      MAP_ANONYMOUS
#define MAP_FAILED    ((void *)-1)

static inline DWORD sh_win_protect(int prot) {
  if (prot & PROT_EXEC) {
    if (prot & PROT_WRITE) return PAGE_EXECUTE_READWRITE;
    return (prot & PROT_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
  }
  if (prot & PROT_WRITE) return PAGE_READWRITE;
  return (prot & PROT_READ) ? PAGE_READONLY : PAGE_NOACCESS;
}

// VirtualAlloc fails on a taken hint where mmap would map elsewhere, so a hint walks the free
// regions above it at the 64 KB allocation granularity before falling back to anywhere.
static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  (void)fd, (void)offset;
  const uintptr_t granule = 0x10000, reach = 0x8000000;
  DWORD protect = sh_win_protect(prot);
  void *p = NULL;
  if (NULL != addr) {
    uintptr_t start = (uintptr_t)addr & ~(granule - 1);
    for (uintptr_t at = start; NULL == p && at - start < reach;) {
      MEMORY_BASIC_INFORMATION info;
      if (0 == VirtualQuery((void *)at, &info, sizeof(info))) break;
      uintptr_t end = (uintptr_t)info.BaseAddress + info.RegionSize;
      if (MEM_FREE == info.State && end - at >= length)
        p = VirtualAlloc((void *)at, length, MEM_RESERVE | MEM_COMMIT, protect);
      if (flags & MAP_FIXED) break;
      at = (end + granule - 1) & ~(granule - 1);
    }
  }
  if (NULL == p && !(flags & MAP_FIXED)) p = VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, protect);
  return NULL == p ? MAP_FAILED : p;
}

static inline int munmap(void *addr, size_t length) {
  (void)length;
  return VirtualFree(addr, 0, MEM_RELEASE) ? 0 : -1;
}

static inline int mprotect(void *addr, size_t len, int prot) {
  DWORD old;
  return VirtualProtect(addr, len, sh_win_protect(prot), &old) ? 0 : -1;
}
