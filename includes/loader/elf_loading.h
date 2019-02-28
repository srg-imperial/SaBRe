#ifndef ELF_LOADING_H
#define ELF_LOADING_H

#include <elf.h>
#include <stddef.h>

#if defined(__x86_64__)                                                      
#define __ELF_NATIVE_CLASS 64
#else                                                                          
#error Unsupported target platform                                             
#endif                                                                         

#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

int elfld_getehdr(int fd, ElfW(Ehdr) *ehdr);

ElfW(Addr) elfld_load_elf(int fd,
                          ElfW(Ehdr) const *ehdr,
                          size_t pagesize,
                          ElfW(Addr) * out_phdr,
                          ElfW(Addr) * out_phnum,
                          ElfW(Addr) * load_bias,
                          const char **out_interp);

#endif /* !ELF_LOADING_H */
