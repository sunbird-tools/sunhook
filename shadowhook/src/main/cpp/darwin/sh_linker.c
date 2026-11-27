#include "sh_linker.h"

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdlib.h>
#include <string.h>

#include "sh_util.h"
#include "sh_xdl.h"
#include "shadowhook.h"

#define SH_LINKER_BOUNDS_MAX 0x10000

typedef struct {
  void *dl;
  const struct mach_header_64 *header;
} sh_linker_handle_t;

typedef struct {
  uintptr_t slide;
  const struct segment_command_64 *linkedit;
  const struct linkedit_data_command *func_starts;
  const struct symtab_command *symtab;
  uintptr_t text_start;
  uintptr_t text_end;
} sh_linker_image_t;

static void sh_linker_parse(const struct mach_header_64 *header, sh_linker_image_t *image) {
  memset(image, 0, sizeof(*image));
  const struct load_command *cmd = (const struct load_command *)(header + 1);
  for (uint32_t i = 0; i < header->ncmds;
       i++, cmd = (const struct load_command *)(const void *)((const uint8_t *)cmd + cmd->cmdsize)) {
    if (LC_SEGMENT_64 == cmd->cmd) {
      const struct segment_command_64 *seg = (const struct segment_command_64 *)(const void *)cmd;
      if (0 == strcmp(seg->segname, SEG_TEXT)) {
        image->slide = (uintptr_t)header - seg->vmaddr;
        const struct section_64 *sect = (const struct section_64 *)(seg + 1);
        for (uint32_t j = 0; j < seg->nsects; j++) {
          if (0 != strcmp(sect[j].sectname, SECT_TEXT)) continue;
          image->text_start = sect[j].addr;
          image->text_end = sect[j].addr + sect[j].size;
        }
      } else if (0 == strcmp(seg->segname, SEG_LINKEDIT)) {
        image->linkedit = seg;
      }
    } else if (LC_FUNCTION_STARTS == cmd->cmd) {
      image->func_starts = (const struct linkedit_data_command *)(const void *)cmd;
    } else if (LC_SYMTAB == cmd->cmd) {
      image->symtab = (const struct symtab_command *)(const void *)cmd;
    }
  }
  image->text_start += image->slide;
  image->text_end += image->slide;
}

// Shared cache images keep these offsets relative to the cache's own __LINKEDIT, which this also covers.
static const void *sh_linker_linkedit(const sh_linker_image_t *image, uint32_t offset) {
  return (const void *)(image->linkedit->vmaddr + image->slide + offset - image->linkedit->fileoff);
}

// LC_FUNCTION_STARTS survives stripping, unlike the symbol table.
static bool sh_linker_func_bounds(const struct mach_header_64 *header, uintptr_t addr, uintptr_t *start,
                                  size_t *len) {
  sh_linker_image_t image;
  sh_linker_parse(header, &image);
  if (NULL == image.linkedit || NULL == image.func_starts) return false;
  if (addr < image.text_start || image.text_end <= addr) return false;

  const uint8_t *p = sh_linker_linkedit(&image, image.func_starts->dataoff);
  const uint8_t *end = p + image.func_starts->datasize;
  uintptr_t func = (uintptr_t)header;
  uintptr_t found = 0;
  while (p < end) {
    uint64_t delta = 0;
    for (unsigned shift = 0; p < end; shift += 7) {
      uint8_t byte = *p++;
      delta |= (uint64_t)(byte & 0x7f) << shift;
      if (0 == (byte & 0x80)) break;
    }
    if (0 == delta) break;
    func += delta;
    if (func > addr) {
      if (0 == found) return false;
      *start = found;
      *len = func - found;
      return true;
    }
    found = func;
  }
  if (0 == found) return false;
  *start = found;
  *len = image.text_end - found;
  return true;
}

static const struct mach_header_64 *sh_linker_find_image(const char *lib_name, const char **path) {
  for (uint32_t i = 0; i < _dyld_image_count(); i++) {
    const char *name = _dyld_get_image_name(i);
    const struct mach_header *header = _dyld_get_image_header(i);
    if (NULL == name || NULL == header || !sh_util_match_pathname(name, lib_name)) continue;
    *path = name;
    return (const struct mach_header_64 *)header;
  }
  return NULL;
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

int sh_linker_get_addr_info_by_addr(sh_addr_info_t *addr_info, void *addr, bool is_sym_addr,
                                    bool is_proc_start, bool ignore_sym_info) {
  sh_linker_free_addr_info(addr_info);
  memset(addr_info, 0, sizeof(sh_addr_info_t));

  Dl_info info;
  if (0 == dladdr(addr, &info) || NULL == info.dli_fbase) return SHADOWHOOK_ERRNO_HOOK_DLINFO;
  if (CPU_TYPE_ARM64 != ((const struct mach_header_64 *)info.dli_fbase)->cputype)
    return SHADOWHOOK_ERRNO_ELF_ARCH_MISMATCH;

  if (!ignore_sym_info) {
    uintptr_t start;
    size_t len;
    if (!sh_linker_func_bounds(info.dli_fbase, (uintptr_t)addr, &start, &len))
      return SHADOWHOOK_ERRNO_HOOK_DLINFO;
    addr_info->dli_saddr = (void *)start;
    addr_info->dli_ssize = len;
  }

  if (NULL != info.dli_fname && NULL == (addr_info->dli_fname = strdup(info.dli_fname)))
    return SHADOWHOOK_ERRNO_OOM;
  addr_info->dli_fbase = info.dli_fbase;
  addr_info->is_sym_addr = is_sym_addr;
  addr_info->is_proc_start = is_proc_start;
  return 0;
}

int sh_linker_get_code_bounds(uintptr_t addr, uintptr_t *start, size_t *len) {
  Dl_info info;
  if (0 == dladdr((void *)addr, &info) || NULL == info.dli_fbase) return -1;
  if (sh_linker_func_bounds(info.dli_fbase, addr, start, len)) return 0;

  sh_linker_image_t image;
  sh_linker_parse(info.dli_fbase, &image);
  if (addr < image.text_start || image.text_end <= addr) return -1;
  *start = addr;
  *len = image.text_end - addr > SH_LINKER_BOUNDS_MAX ? SH_LINKER_BOUNDS_MAX : image.text_end - addr;
  return 0;
}

int sh_linker_get_addr_info_by_name(sh_addr_info_t *addr_info, const char *lib_name, const char *sym_name) {
  sh_linker_free_addr_info(addr_info);
  memset(addr_info, 0, sizeof(sh_addr_info_t));

  void *handle = sh_xdl_open(lib_name);
  if (NULL == handle) return SHADOWHOOK_ERRNO_NOT_FOUND;
  size_t sym_size = 0;
  void *sym_addr = sh_xdl_sym(handle, sym_name, &sym_size);
  sh_xdl_close(handle);
  if (NULL == sym_addr) return SHADOWHOOK_ERRNO_HOOK_DLSYM;

  // dlsym follows re-exports, so the symbol may live in another image.
  Dl_info info;
  if (0 == dladdr(sym_addr, &info) || NULL == info.dli_fbase) return SHADOWHOOK_ERRNO_HOOK_DLINFO;

  if (NULL == (addr_info->dli_fname = strdup(lib_name))) return SHADOWHOOK_ERRNO_OOM;
  addr_info->dli_fbase = info.dli_fbase;
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

void *sh_xdl_open(const char *lib_name) {
  const char *path = lib_name;
  const struct mach_header_64 *header = sh_linker_find_image(lib_name, &path);
  void *dl = dlopen(path, RTLD_NOLOAD | RTLD_LAZY | RTLD_LOCAL);
  if (NULL == dl) return NULL;

  // dlopen() resolved lib_name some other way, such as through an @rpath install name.
  for (uint32_t i = 0; NULL == header && i < _dyld_image_count(); i++) {
    void *other = dlopen(_dyld_get_image_name(i), RTLD_NOLOAD | RTLD_LAZY | RTLD_LOCAL);
    if (other == dl) header = (const struct mach_header_64 *)_dyld_get_image_header(i);
    if (NULL != other) dlclose(other);
  }
  sh_linker_handle_t *handle = NULL;
  if (NULL == header || NULL == (handle = malloc(sizeof(*handle)))) {
    dlclose(dl);
    return NULL;
  }
  handle->dl = dl;
  handle->header = header;
  return handle;
}

void sh_xdl_close(void *handle) {
  if (NULL == handle) return;
  sh_linker_handle_t *self = handle;
  dlclose(self->dl);
  free(self);
}

static void sh_linker_set_size(sh_linker_handle_t *self, void *addr, size_t *symbol_size) {
  if (NULL == symbol_size) return;
  uintptr_t start;
  size_t len;
  *symbol_size = 0;
  if (NULL == addr) return;
  Dl_info info;
  const struct mach_header_64 *header = self->header;
  if (0 != dladdr(addr, &info) && NULL != info.dli_fbase) header = info.dli_fbase;
  if (sh_linker_func_bounds(header, (uintptr_t)addr, &start, &len) && start == (uintptr_t)addr)
    *symbol_size = len;
}

void *sh_xdl_sym_dynsym(void *handle, const char *sym_name, size_t *symbol_size) {
  sh_linker_handle_t *self = handle;
  void *addr = dlsym(self->dl, sym_name);
  sh_linker_set_size(self, addr, symbol_size);
  return addr;
}

void *sh_xdl_sym_symtab(void *handle, const char *sym_name, size_t *symbol_size) {
  sh_linker_handle_t *self = handle;
  sh_linker_image_t image;
  sh_linker_parse(self->header, &image);
  void *addr = NULL;
  if (NULL != image.linkedit && NULL != image.symtab) {
    const struct nlist_64 *syms = sh_linker_linkedit(&image, image.symtab->symoff);
    const char *strs = sh_linker_linkedit(&image, image.symtab->stroff);
    for (uint32_t i = 0; i < image.symtab->nsyms; i++) {
      const struct nlist_64 *sym = &syms[i];
      if ((sym->n_type & N_STAB) || N_SECT != (sym->n_type & N_TYPE)) continue;
      if (sym->n_un.n_strx >= image.symtab->strsize) continue;
      const char *name = strs + sym->n_un.n_strx;
      if ('_' != name[0] || 0 != strcmp(name + 1, sym_name)) continue;
      addr = (void *)(sym->n_value + image.slide);
      break;
    }
  }
  sh_linker_set_size(self, addr, symbol_size);
  return addr;
}

void *sh_xdl_sym(void *handle, const char *sym_name, size_t *symbol_size) {
  void *addr = sh_xdl_sym_dynsym(handle, sym_name, symbol_size);
  return NULL != addr ? addr : sh_xdl_sym_symtab(handle, sym_name, symbol_size);
}
