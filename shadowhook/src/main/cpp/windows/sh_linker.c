#include "sh_linker.h"

#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "sh_util.h"
#include "sh_xdl.h"
#include "shadowhook.h"

#define SH_LINKER_BOUNDS_MAX 0x10000

static HMODULE sh_linker_module_of(uintptr_t addr) {
  HMODULE module = NULL;
  if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCWSTR)addr, &module))
    return NULL;
  return module;
}

static const IMAGE_NT_HEADERS64 *sh_linker_nt_headers(uintptr_t base) {
  const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
  if (IMAGE_DOS_SIGNATURE != dos->e_magic) return NULL;
  const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)(base + (uintptr_t)dos->e_lfanew);
  if (IMAGE_NT_SIGNATURE != nt->Signature || IMAGE_NT_OPTIONAL_HDR64_MAGIC != nt->OptionalHeader.Magic)
    return NULL;
  return nt;
}

static bool sh_linker_code_section(uintptr_t base, uintptr_t addr, uintptr_t *start, uintptr_t *end) {
  const IMAGE_NT_HEADERS64 *nt = sh_linker_nt_headers(base);
  if (NULL == nt) return false;
  const IMAGE_SECTION_HEADER *sect = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
    uintptr_t lo = base + sect[i].VirtualAddress;
    uintptr_t hi = lo + sect[i].Misc.VirtualSize;
    if (!(sect[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) || addr < lo || hi <= addr) continue;
    *start = lo;
    *end = hi;
    return true;
  }
  return false;
}

// The .pdata entry covering rva in *found, else in *next the first entry past it. Entries are sorted by
// BeginAddress, and a fragment chained to its primary through UNW_FLAG_CHAININFO keeps its own range.
static void sh_linker_pdata(uintptr_t base, DWORD rva, const RUNTIME_FUNCTION **found,
                            const RUNTIME_FUNCTION **next) {
  *found = NULL;
  *next = NULL;
  const IMAGE_NT_HEADERS64 *nt = sh_linker_nt_headers(base);
  if (NULL == nt || nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) return;
  const IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
  const RUNTIME_FUNCTION *funcs = (const RUNTIME_FUNCTION *)(base + dir->VirtualAddress);
  size_t lo = 0, hi = dir->Size / sizeof(RUNTIME_FUNCTION);
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (funcs[mid].EndAddress <= rva)
      lo = mid + 1;
    else
      hi = mid;
  }
  if (lo == dir->Size / sizeof(RUNTIME_FUNCTION)) return;
  if (funcs[lo].BeginAddress <= rva)
    *found = &funcs[lo];
  else
    *next = &funcs[lo];
}

// Leaves have no unwind data, so their bounds run from addr to the next function that has some.
int sh_linker_get_code_bounds(uintptr_t addr, uintptr_t *start, size_t *len) {
  uintptr_t base = (uintptr_t)sh_linker_module_of(addr);
  uintptr_t text_start, text_end;
  if (0 == base || !sh_linker_code_section(base, addr, &text_start, &text_end)) return -1;

  const RUNTIME_FUNCTION *found, *next;
  sh_linker_pdata(base, (DWORD)(addr - base), &found, &next);
  if (NULL != found) {
    *start = base + found->BeginAddress;
    *len = found->EndAddress - found->BeginAddress;
    return 0;
  }

  uintptr_t end = text_end;
  if (end - addr > SH_LINKER_BOUNDS_MAX) end = addr + SH_LINKER_BOUNDS_MAX;
  if (NULL != next && base + next->BeginAddress < end) end = base + next->BeginAddress;
  *start = addr;
  *len = end - addr;
  return 0;
}

int sh_linker_init(void) {
  return 0;
}

int sh_linker_register_dl_init_callback(shadowhook_dl_info_t pre, shadowhook_dl_info_t post, void *data) {
  (void)pre, (void)post, (void)data;
  return SHADOWHOOK_ERRNO_NOT_SUPPORT;
}

int sh_linker_unregister_dl_init_callback(shadowhook_dl_info_t pre, shadowhook_dl_info_t post, void *data) {
  (void)pre, (void)post, (void)data;
  return SHADOWHOOK_ERRNO_NOT_SUPPORT;
}

int sh_linker_register_dl_fini_callback(shadowhook_dl_info_t pre, shadowhook_dl_info_t post, void *data) {
  (void)pre, (void)post, (void)data;
  return SHADOWHOOK_ERRNO_NOT_SUPPORT;
}

int sh_linker_unregister_dl_fini_callback(shadowhook_dl_info_t pre, shadowhook_dl_info_t post, void *data) {
  (void)pre, (void)post, (void)data;
  return SHADOWHOOK_ERRNO_NOT_SUPPORT;
}

static int sh_linker_fill(sh_addr_info_t *addr_info, HMODULE module) {
  char path[MAX_PATH];
  DWORD n = GetModuleFileNameA(module, path, sizeof(path));
  if (0 != n && n < sizeof(path) && NULL == (addr_info->dli_fname = strdup(path))) return SHADOWHOOK_ERRNO_OOM;
  addr_info->dli_fbase = (void *)module;
  return 0;
}

int sh_linker_get_addr_info_by_addr(sh_addr_info_t *addr_info, void *addr, bool is_sym_addr,
                                    bool is_proc_start, bool ignore_sym_info) {
  sh_linker_free_addr_info(addr_info);
  memset(addr_info, 0, sizeof(sh_addr_info_t));

  HMODULE module = sh_linker_module_of((uintptr_t)addr);
  if (NULL == module) return SHADOWHOOK_ERRNO_HOOK_DLINFO;

  if (!ignore_sym_info) {
    uintptr_t start;
    size_t len;
    if (0 != sh_linker_get_code_bounds((uintptr_t)addr, &start, &len)) return SHADOWHOOK_ERRNO_HOOK_DLINFO;
    addr_info->dli_saddr = (void *)start;
    addr_info->dli_ssize = len;
  }

  int r = sh_linker_fill(addr_info, module);
  if (0 != r) return r;
  addr_info->is_sym_addr = is_sym_addr;
  addr_info->is_proc_start = is_proc_start;
  return 0;
}

int sh_linker_get_addr_info_by_name(sh_addr_info_t *addr_info, const char *lib_name, const char *sym_name) {
  sh_linker_free_addr_info(addr_info);
  memset(addr_info, 0, sizeof(sh_addr_info_t));

  HMODULE module = GetModuleHandleA(lib_name);
  if (NULL == module) return SHADOWHOOK_ERRNO_NOT_FOUND;
  size_t sym_size = 0;
  void *sym_addr = sh_xdl_sym(module, sym_name, &sym_size);
  if (NULL == sym_addr) return SHADOWHOOK_ERRNO_HOOK_DLSYM;

  // GetProcAddress follows forwarders, so the symbol may live in another module.
  HMODULE owner = sh_linker_module_of((uintptr_t)sym_addr);
  if (NULL == owner) return SHADOWHOOK_ERRNO_HOOK_DLINFO;
  int r = sh_linker_fill(addr_info, owner);
  if (0 != r) return r;
  addr_info->dli_saddr = sym_addr;
  addr_info->dli_ssize = sym_size;
  addr_info->is_sym_addr = true;
  addr_info->is_proc_start = true;
  return 0;
}

void sh_linker_free_addr_info(sh_addr_info_t *addr_info) {
  if (NULL != addr_info->dli_fname) {
    free(addr_info->dli_fname);
    addr_info->dli_fname = NULL;
  }
}

int sh_linker_copy_addr_info(sh_addr_info_t *addr_info, sh_addr_info_t *copy) {
  memcpy(copy, addr_info, sizeof(sh_addr_info_t));
  if (NULL != addr_info->dli_fname) {
    copy->dli_fname = strdup(addr_info->dli_fname);
    if (NULL == copy->dli_fname) return SHADOWHOOK_ERRNO_OOM;
  }
  return 0;
}

// Handles are module bases of already loaded modules, as with RTLD_NOLOAD elsewhere.
void *sh_xdl_open(const char *lib_name) {
  return (void *)GetModuleHandleA(lib_name);
}

void sh_xdl_close(void *handle) {
  (void)handle;
}

void *sh_xdl_sym_dynsym(void *handle, const char *sym_name, size_t *symbol_size) {
  void *addr = (void *)GetProcAddress((HMODULE)handle, sym_name);
  if (NULL != symbol_size) {
    uintptr_t start;
    size_t len;
    *symbol_size = 0;
    if (NULL != addr && 0 == sh_linker_get_code_bounds((uintptr_t)addr, &start, &len) && start == (uintptr_t)addr)
      *symbol_size = len;
  }
  return addr;
}

void *sh_xdl_sym_symtab(void *handle, const char *sym_name, size_t *symbol_size) {
  (void)handle, (void)sym_name;
  if (NULL != symbol_size) *symbol_size = 0;
  return NULL;
}

void *sh_xdl_sym(void *handle, const char *sym_name, size_t *symbol_size) {
  return sh_xdl_sym_dynsym(handle, sym_name, symbol_size);
}
