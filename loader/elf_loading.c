/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <fcntl.h>
#include <gelf.h>
#include <limits.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "elf_loading.h"
#include "macros.h"

#define MAX_PHNUM 16

GElf_Sym find_elf_symbol(const char *elf_path, const char *sym_name) {
  // TODO(andronat): This opens a file. Can we make it faster?
  Elf *elf;
  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  Elf_Data *data;
  int fd, count;
  GElf_Sym rv;

  if (elf_version(EV_CURRENT) == EV_NONE)
    _nx_fatal_printf("ELF library initialization failed\n");

  fd = open(elf_path, O_RDONLY);
  elf = elf_begin(fd, ELF_C_READ, NULL);

  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type == SHT_SYMTAB) {
      // Found a symbol table.
      break;
    }
  }

  data = elf_getdata(scn, NULL);
  count = shdr.sh_size / shdr.sh_entsize;

  // Go through symbols
  for (int i = 0; i < count; ++i) {
    GElf_Sym sym;
    gelf_getsym(data, i, &sym);
    if (!strcmp(sym_name, elf_strptr(elf, shdr.sh_link, sym.st_name))) {
      rv = sym;
      break;
    }
  }

  elf_end(elf);
  close(fd);
  return rv;
}

ElfW(Addr) addr_of_elf_symbol(const char *elf_path, const char *sym_name) {
  return find_elf_symbol(elf_path, sym_name).st_value;
}

static int prot_from_phdr(const ElfW(Phdr) * phdr) {
  int prot = 0;
  if (phdr->p_flags & PF_R)
    prot |= PROT_READ;
  if (phdr->p_flags & PF_W)
    prot |= PROT_WRITE;
  if (phdr->p_flags & PF_X)
    prot |= PROT_EXEC;
  return prot;
}

/*
 * Handle the "bss" portion of a segment, where the memory size
 * exceeds the file size and we zero-fill the difference.  For any
 * whole pages in this region, we over-map anonymous pages.  For the
 * sub-page remainder, we zero-fill bytes directly.
 */
static void handle_bss(const ElfW(Phdr) * ph,
                       ElfW(Addr) load_bias,
                       size_t pagesize) {
  if (ph->p_memsz > ph->p_filesz) {
    ElfW(Addr) file_end = ph->p_vaddr + load_bias + ph->p_filesz;
    ElfW(Addr) file_page_end = round_up(file_end, pagesize);
    ElfW(Addr) page_end =
        round_up(ph->p_vaddr + load_bias + ph->p_memsz, pagesize);
    if (page_end > file_page_end) {
      void *result;
      result = mmap((void *)file_page_end,
                    page_end - file_page_end,
                    prot_from_phdr(ph),
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                    -1,
                    0);
      if ((void *)result == MAP_FAILED) {
        _nx_fatal_printf("Failed to map segment.\n");
      }
    }
    if (file_page_end > file_end && (ph->p_flags & PF_W)) {
      memset((void *)file_end, 0, file_page_end - file_end);
    }
  }
}


int elfld_getehdr(int fd, ElfW(Ehdr) *ehdr) {
  int result;

  result = pread(fd, ehdr, sizeof(*ehdr), 0);
  if (result < 0) {
    _nx_fatal_printf("Failed to read ELF header from file\n");
  }
  if ((size_t)result != sizeof(*ehdr)) {
    _nx_fatal_printf("Read count\n");
  }

  if (ehdr->e_ident[EI_MAG0] != ELFMAG0 || ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
      ehdr->e_ident[EI_MAG2] != ELFMAG2 || ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
      ehdr->e_version != EV_CURRENT || ehdr->e_ehsize != sizeof(*ehdr) ||
      ehdr->e_phentsize != sizeof(ElfW(Phdr))) {
    _nx_fatal_printf("File has no valid ELF header!\n");
  }


#ifdef __x86_64__
    if (ehdr->e_machine != EM_X86_64)
#elif defined(__riscv)
    if (ehdr->e_machine != EM_RISCV)
#endif
      _nx_fatal_printf("ELF file has wrong architecture (%u)\n",
                       ehdr->e_machine);

  return 0;
}

ElfW(Addr) elfld_load_elf(int fd, ElfW(Ehdr) const *ehdr, size_t pagesize,
                          ElfW(Addr) * out_phdr, ElfW(Addr) * out_phnum,
                          const char **out_interp) {
  ssize_t result;

  ElfW(Phdr) phdr[MAX_PHNUM];
  if (ehdr->e_phnum > sizeof(phdr) / sizeof(phdr[0]) || ehdr->e_phnum < 1) {
    _nx_fatal_printf("ELF file has unreasonable e_phnum %u", ehdr->e_phnum);
  }

  result = pread(fd, phdr, sizeof(phdr[0]) * ehdr->e_phnum, ehdr->e_phoff);
  if (result < 0) {
    _nx_fatal_printf("Failed to read program headers from ELF file\n");
  }
  if ((size_t)result != sizeof(phdr[0]) * ehdr->e_phnum) {
    _nx_fatal_printf("Read from file failed\n");
  }

  size_t i = 0;
  while (i < ehdr->e_phnum && phdr[i].p_type != PT_LOAD) {
    ++i;
  }
  if (i == ehdr->e_phnum) {
    _nx_fatal_printf("ELF file has no PT_LOAD header!");
  }

  /*
   * ELF requires that PT_LOAD segments be in ascending order of p_vaddr.
   * Find the last one to calculate the whole address span of the image.
   */
  const ElfW(Phdr) *first_load = &phdr[i];
  const ElfW(Phdr) *last_load = &phdr[ehdr->e_phnum - 1];
  while (last_load > first_load && last_load->p_type != PT_LOAD)
    --last_load;

  size_t span = last_load->p_vaddr + last_load->p_memsz - first_load->p_vaddr;

  /*
   * Map the first segment and reserve the space used for the rest and
   * for holes between segments.
   */
  uintptr_t mapping;
  mapping = (uintptr_t)mmap((void *)round_down(first_load->p_vaddr, pagesize),
                            span, prot_from_phdr(first_load), MAP_PRIVATE, fd,
                            round_down(first_load->p_offset, pagesize));

  if ((void *)mapping == MAP_FAILED) {
    _nx_fatal_printf("Failed to map segment.\n");
  }

  ElfW(Addr) load_bias = mapping - round_down(first_load->p_vaddr, pagesize);

  if (first_load->p_offset > ehdr->e_phoff ||
      first_load->p_filesz <
          ehdr->e_phoff + (ehdr->e_phnum * sizeof(ElfW(Phdr)))) {
    _nx_fatal_printf("First load segment of ELF file does not contain phdrs!");
  }

  handle_bss(first_load, load_bias, pagesize);

  ElfW(Addr) last_end = first_load->p_vaddr + load_bias + first_load->p_memsz;

  /*
   * Map the remaining segments, and protect any holes between them.
   */
  const ElfW(Phdr) * ph;
  for (ph = first_load + 1; ph <= last_load; ++ph) {
    if (ph->p_type == PT_LOAD) {
      ElfW(Addr) last_page_end = round_up(last_end, pagesize);

      last_end = ph->p_vaddr + load_bias + ph->p_memsz;
      ElfW(Addr) start = round_down(ph->p_vaddr + load_bias, pagesize);
      ElfW(Addr) end = round_up(last_end, pagesize);

      if (start > last_page_end) {
        mprotect((void *)last_page_end, start - last_page_end, PROT_NONE);
      }

      mmap((void *)start, end - start, prot_from_phdr(ph),
           MAP_PRIVATE | MAP_FIXED, fd, round_down(ph->p_offset, pagesize));

      handle_bss(ph, load_bias, pagesize);
    }
  }

  if (out_interp != NULL) {
    /*
     * Find the PT_INTERP header, if there is one.
     */
    for (ElfW(Half) i = 0; i < ehdr->e_phnum; ++i) {
      if (phdr[i].p_type == PT_INTERP) {
        /*
         * The PT_INTERP isn't really required to sit inside the first
         * (or any) load segment, though it normally does.  So we can
         * easily avoid an extra read in that case.
         */
        if (phdr[i].p_offset >= first_load->p_offset &&
            phdr[i].p_filesz <= first_load->p_filesz) {
          *out_interp = (const char *)(phdr[i].p_vaddr + load_bias);
        } else {
          static char interp_buffer[PATH_MAX + 1];
          if (phdr[i].p_filesz >= sizeof(interp_buffer)) {
            _nx_fatal_printf(
                "ELF file has unreasonable PT_INTERP size %lu in segment %u\n",
                phdr[i].p_filesz, i);
          }
          result = pread(fd, interp_buffer, phdr[i].p_filesz, phdr[i].p_offset);
          if (result < 0) {
            _nx_fatal_printf("Cannot read PT_INTERP segment contents\n");
          }
          if ((size_t)result != phdr[i].p_filesz) {
            _nx_fatal_printf("Read from file failed\n");
          }
          *out_interp = interp_buffer;
        }
        break;
      }
    }
  }

  if (out_phdr != NULL) {
    *out_phdr = (ehdr->e_phoff - first_load->p_offset + first_load->p_vaddr +
                 load_bias);
  }
  if (out_phnum != NULL) {
    *out_phnum = ehdr->e_phnum;
  }

  return ehdr->e_entry + load_bias;
}
