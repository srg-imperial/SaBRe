#ifndef LIBRARY_H_
#define LIBRARY_H_

#include <elf.h>
#include <stdbool.h>
#include <sys/types.h>

#include "compiler.h"
#include "maps.h"

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;

struct symbol {
  const char *name;
  Elf_Sym sym;
  struct hlist_node symbol_hash;
};

/* Internal data structure for segments. */
struct segment {
  uint64_t addr; /* load addr */
  uint64_t off;  /* file offset */
  uint64_t fsz;  /* file size */
  uint64_t msz;  /* memory size */
  uint64_t type; /* segment type */

  struct list_head section_list;
  struct list_head segments;
};

/* Internal data structure for sections. */
struct section {
  struct segment *seg; /* containing segment */
  const char *name;    /* section name */
  int idx;             /* secton index */
  Elf_Shdr shdr;       /* section header */
  void *buf;           /* section content */
  uint8_t *pad;        /* section padding */
  uint64_t off;        /* section offset */
  uint64_t sz;         /* section size */
  uint64_t cap;        /* section capacity */
  uint64_t align;      /* section alignment */
  uint64_t type;       /* section type */
  uint64_t vma;        /* section virtual addr */
  uint64_t lma;        /* section load addr */
  uint64_t pad_sz;     /* section padding size */
  int loadable;        /* whether loadable */
  int pseudo;
  int nocopy;

  struct list_head sections;
  struct list_head seg_entry; /* list of sections in a segment */
  struct hlist_node section_hash;
};

struct library {
  char *pathname;
  bool valid;
  bool vdso; // TODO(andronat): remove this field
  char *asr_offset;
  int vsys_offset; // TODO(andronat): remove this field
  Elf_Ehdr ehdr;
  struct rb_root rb_region;
  struct hlist_head *section_hash;
  struct hlist_head *symbol_hash;
  char *image;
  size_t image_size;
  struct maps *maps; // TODO(andronat): do we really need this?
  struct hlist_node library_hash;
};

extern char *__kernel_vsyscall __internal;
extern char *__kernel_sigreturn __internal;
extern char *__kernel_rt_sigreturn __internal;

extern char *__vdso_gettimeofday __internal;
extern char *__vdso_getcpu __internal;
extern char *__vdso_clock_gettime __internal;
extern char *__vdso_time __internal;


void library_init(struct library *,
                  const char *name,
                  struct maps *maps) attribute_hidden;
bool library_parse_elf(struct library *, const char *) attribute_hidden;


int which_lib_name_interesting(const char * interesting_libs[], const char * pathname);

void memorymaps_rewrite_all(const char* libs[], const char* bin, bool loader);
void memorymaps_rewrite_lib(const char* libname);

#endif /* LIBRARY_H_ */
