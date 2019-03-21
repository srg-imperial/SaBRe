#ifndef ELF_LOADING_H
#define ELF_LOADING_H

#include <elf.h>
#include <link.h>
#include <stddef.h>

int elfld_getehdr(int fd, ElfW(Ehdr) *ehdr);

ElfW(Addr) elfld_load_elf(int fd,
                          ElfW(Ehdr) const *ehdr,
                          size_t pagesize,
                          ElfW(Addr) * out_phdr,
                          ElfW(Addr) * out_phnum,
                          ElfW(Addr) * load_bias,
                          const char **out_interp);

#endif /* !ELF_LOADING_H */
