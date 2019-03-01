#ifndef LIBRARY_H_
#define LIBRARY_H_

#include <elf.h>
#include <stdbool.h>
#include <sys/types.h>

#include "compiler.h"
#include "loader/maps.h"

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;

struct symbol {
  const char *name;
  Elf_Sym sym;
  struct hlist_node symbol_hash;
};

/* Internal data structure for sections. */
struct section {
  const char *name;    /* section name */
  Elf_Shdr shdr;       /* section header */
  struct hlist_node section_hash;
};

struct library {
  char *pathname;
  bool valid;
  bool vdso;
  char *asr_offset;
  Elf_Ehdr ehdr;
  struct rb_root rb_region;
  struct hlist_head *section_hash;
  struct hlist_head *symbol_hash;
  char *image;
  size_t image_size;
  struct maps *maps; // TODO(andronat): do we really need this?
  struct hlist_node library_hash;
};

int which_lib_name_interesting(const char * interesting_libs[], const char * pathname);
void memorymaps_rewrite_all(const char* libs[], const char* bin, bool loader);
void memorymaps_rewrite_lib(const char* libname);

#endif /* LIBRARY_H_ */
