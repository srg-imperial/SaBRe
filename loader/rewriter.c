#include "config.h"
#include "rewriter.h"

#include <assert.h>
#include <string.h>
#include <stddef.h>

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/socket.h>

#include "compiler.h"
#include "hlist.h"
#include "jhash.h"
#include "list.h"
#include "rbtree.h"

#include "x86_decoder.h"
#include "macros.h"
#include "global_vars.h"

#include "handle_syscall.h"
#include "handle_syscall_loader.h"
#include "handle_vdso.h"
#include "handle_rdtsc.h"

typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_Rela Elf_Rel;

typedef Elf64_Half Elf_Half;
typedef Elf64_Word Elf_Word;
typedef Elf64_Sword Elf_Sword;
typedef Elf64_Xword Elf_Xword;
typedef Elf64_Sxword Elf_Sxword;
typedef Elf64_Off Elf_Off;
typedef Elf64_Section Elf_Section;
typedef Elf64_Versym Elf_Versym;

char *__kernel_sigreturn __internal;
char *__kernel_rt_sigreturn __internal;

#define section_hashfn(n) jhash(n, strlen(n), 0) & (sectionhash_size - 1)
#define sectionhash_size 16
#define sectionhash_shift 4

static inline void section_init(struct section *s,
                                const char *name,
                                int idx,
                                Elf_Shdr shdr) {
  s->name = name;
  s->idx = idx;
  s->shdr = shdr;  // TODO: should we use malloc + memcpy

  INIT_LIST_HEAD(&s->sections);
  INIT_LIST_HEAD(&s->seg_entry);
  INIT_HLIST_NODE(&s->section_hash);
}

static inline struct section *section_find(struct hlist_head *hash,
                                           const char *name) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct section *s;

  // head = &lib->section_hash[hash & (sectionhash_size - 1)];
  head = &hash[section_hashfn(name)];
  _nx_debug_printf(
      "search: %s = %u (%zu)\n", name, section_hashfn(name), strlen(name));
  hlist_for_each_entry(s, node, head, section_hash) {
    if (strcmp(name, s->name) == 0)
      return s;
  }

  return NULL;
}

static inline void section_add(struct hlist_head *hash, struct section *scn) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct section *s;

  head = &hash[section_hashfn(scn->name)];
  _nx_debug_printf("add: %s = %u (%zu)\n",
                   scn->name,
                   section_hashfn(scn->name),
                   strlen(scn->name));
  hlist_for_each_entry(s, node, head, section_hash) {
    if (strcmp(scn->name, s->name) == 0)
      return;
  }

  hlist_add_head(&scn->section_hash, head);
}

#define symbol_hashfn(n) jhash(n, strlen(n), 0) & (symbolhash_size - 1)
#define symbolhash_size 16
#define symbolhash_shift 4

static inline void symbol_init(struct symbol *s,
                               const char *name,
                               Elf_Sym sym) {
  s->name = name;
  s->sym = sym;
}

static inline struct symbol *symbol_find(struct hlist_head *hash,
                                         const char *name) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct symbol *s;

  head = &hash[symbol_hashfn(name)];
  hlist_for_each_entry(s, node, head, symbol_hash) {
    if (strcmp(name, s->name) == 0)
      return s;
  }

  return NULL;
}

static inline void symbol_add(struct hlist_head *hash, struct symbol *sym) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct symbol *s;

  head = &hash[symbol_hashfn(sym->name)];
  hlist_for_each_entry(s, node, head, symbol_hash) {
    if (strcmp(sym->name, s->name) == 0)
      return;
  }

  hlist_add_head(&sym->symbol_hash, head);
}

#define rb_entry_region(node) rb_entry((node), struct region, rb_region)

static inline struct region *rb_search_region(struct library *lib,
                                              Elf_Addr offset) {
  struct rb_node *n = lib->rb_region.rb_node;
  struct region *region;

  while (n) {
    region = rb_entry_region(n);

    if (offset > region->offset)
      n = n->rb_left;
    else if (offset < region->offset)
      n = n->rb_right;
    else
      return region;
  }
  return NULL;
}

/**
 * Returns an iterator pointing to the first region whose offset does not
 * compare less than @p offset
 */
static inline struct region *rb_lower_bound_region(struct library *lib,
                                                   Elf_Addr offset) {
  struct rb_node *n = lib->rb_region.rb_node;
  struct rb_node *parent = NULL;
  struct region *region;

  while (n) {
    region = rb_entry_region(n);

    if (!(region->offset > offset)) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_region(parent) : NULL;
}

/**
 * Returns an iterator pointing to the first region whose offset compares
 * greater than @p offset
 */
static inline struct region *rb_upper_bound_region(struct library *lib,
                                                   Elf_Addr offset) {
  struct rb_node *n = lib->rb_region.rb_node;
  struct rb_node *parent = NULL;
  struct region *region;

  while (n) {
    region = rb_entry_region(n);

    if (region->offset < offset) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_region(parent) : NULL;
}

struct branch_target {
  char *addr;
  struct rb_node rb_target;
};

#define rb_entry_target(node) rb_entry((node), struct branch_target, rb_target)

static inline struct branch_target *rb_search_target(struct rb_root *root,
                                                     char *addr) {
  struct rb_node *n = root->rb_node;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (addr < target->addr)
      n = n->rb_left;
    else if (addr > target->addr)
      n = n->rb_right;
    else
      return target;
  }
  return NULL;
}

/**
 * Returns a pointer pointing to the first target whose address does not compare
 * less than @p addr
 */
static inline struct branch_target *rb_lower_bound_target(struct rb_root *root,
                                                          char *addr) {
  struct rb_node *n = root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (!(target->addr < addr)) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_target(parent) : NULL;
}

/**
 * Returns an iterator pointing to the first target whose address compares
 * greater than @p addr
 */
static inline struct branch_target *rb_upper_bound_target(struct rb_root *root,
                                                          char *addr) {
  struct rb_node *n = root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (target->addr > addr) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_target(parent) : NULL;
}

static inline struct branch_target *__rb_insert_target(struct rb_root *root,
                                                       char *addr,
                                                       struct rb_node *node) {
  struct rb_node **p = &root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (*p) {
    parent = *p;
    target = rb_entry(parent, struct branch_target, rb_target);

    if (addr < target->addr)
      p = &(*p)->rb_left;
    else if (addr > target->addr)
      p = &(*p)->rb_right;
    else
      return target;
  }

  rb_link_node(node, parent, p);

  return NULL;
}

static inline struct branch_target *rb_insert_target(struct rb_root *root,
                                                     char *addr,
                                                     struct rb_node *node) {
  struct branch_target *ret;
  if ((ret = __rb_insert_target(root, addr, node)))
    goto out;
  rb_insert_color(node, root);
out:
  return ret;
}

inline void library_init(struct library *l,
                         const char *name,
                         struct maps *maps) {
  l->pathname = strdup(name);

  l->rb_region = RB_ROOT;
  l->section_hash = malloc(sizeof(struct hlist_head) * sectionhash_size);
  for (int i = 0; i < sectionhash_size; i++)
    INIT_HLIST_HEAD(&l->section_hash[i]);
  l->symbol_hash = malloc(sizeof(struct hlist_head) * symbolhash_size);
  for (int i = 0; i < symbolhash_size; i++)
    INIT_HLIST_HEAD(&l->symbol_hash[i]);

  INIT_HLIST_NODE(&l->library_hash);

  l->valid = false;
  l->vdso = false;
  l->asr_offset = 0;
  l->image = NULL;
  l->image_size = 0;
  l->maps = maps;
}

void library_release(struct library *lib) {
  free(lib->pathname);
  free(lib->section_hash);
  free(lib->symbol_hash);
}

// TODO(andronat): Mechanism to destroy custom allocated regions
void library_destroy(struct library *lib) {
  if (!lib->image_size)
    return;

  mprotect(lib->image, 4096, PROT_READ | PROT_WRITE | PROT_EXEC);

  struct rb_node *node = rb_last(&lib->rb_region);
  if (node) {
    struct region *reg = rb_entry_region(node);
    if (memcmp(lib->image, reg->start, 4096)) {
      /* only copy data, if we made any changes in this data */
      memcpy(lib->image, reg->start, 4096);
    }
    mprotect(lib->image, 4096, PROT_READ | PROT_EXEC);
    mremap(lib->image,
               lib->image_size,
               4096,
               MREMAP_MAYMOVE | MREMAP_FIXED,
               reg->start);
  }
}

static char *memcpy_fromlib(void *dst,
                            const void *src,
                            size_t len,
                            struct library *lib) {
  // Some kernels don't allow accessing the VDSO from write()
  if (lib->vdso && src >= rb_entry_region(rb_first(&lib->rb_region))->start &&
      src <= rb_entry_region(rb_first(&lib->rb_region))->end) {
    ptrdiff_t max = rb_entry_region(rb_first(&lib->rb_region))->end - src;
    memcpy(dst, src, clamp_val(len, 0, max));
    return dst;
  }

  // Read up to "len" bytes from "src" and copy them to "dst". Short copies
  // are possible, if we are at the end of a mapping. Returns NULL, if the
  // operation failed completely. Copy data through a socketpair, as this
  // allows us to access it without incurring a segmentation fault.
  static int socket[2];
  if (!socket[0] && !socket[1])
    socketpair(AF_UNIX, SOCK_STREAM, 0, socket);

  char *ptr = dst;
  int inc = 4096;
  while (len > 0) {
    ssize_t l = inc == 1 ? inc : 4096 - ((long)src & 0xFFF);
    if ((size_t)l > len) {
      l = len;
    }
    l = NOINTR(write(socket[0], src, l));
    if (l == -1) {
      if (errno == EFAULT) {
        if (inc == 1) {
          if (ptr == dst) {
            return NULL;
          }
          break;
        }
        inc = 1;
        continue;
      } else {
        return NULL;
      }
    }
    l = NOINTR(read(socket[1], ptr, l));
    if (l <= 0) {
      return NULL;
    }
    ptr += l;
    src += l;
    len -= l;
  }
  return dst;
}

static char *library_buf_get(struct library *lib,
                             Elf_Addr offset,
                             char *buf,
                             size_t len) {
  memset(buf, 0, len);

  if (!lib->valid)
    return NULL;

  _nx_debug_printf("library_buf_get: search for lower bound 0x%lx\n",
                   offset);
  struct region *reg = rb_lower_bound_region(lib, offset);
  if (!reg)
    return NULL;

  _nx_debug_printf("library_buf_get: lower bound found 0x%lx (%p-%p)\n",
                   reg->offset,
                   reg->start,
                   reg->end);
  offset -= reg->offset;
  if (offset > reg->size - len)
    return NULL;

  char *src = (char *)(reg->start) + offset;
  _nx_debug_printf("library_buf_get: copy 0x%lx bytes from %p\n", len, src);
  if (!memcpy_fromlib(buf, src, len, lib))
    return NULL;

  return buf;
}

static char* library_buf_get_original(struct library *l,
                                      Elf_Addr offset,
                                      char *buf,
                                      size_t len) {
  if (!l->valid) {
    if (buf != NULL)
      memset(buf, 0, len);
    return NULL;
  }

  _nx_debug_printf("library_buf_get_original: offset 0x%lx\n", offset);

    struct region *first = rb_entry_region(rb_last(&l->rb_region));
  if (!l->image && !l->vdso && !RB_EMPTY_ROOT(&l->rb_region) &&
      first->offset == 0) {
    _nx_debug_printf("library_buf_get_original: image missing and not VDSO\n");
    // Extend the mapping of the very first page of the underlying library
    // file. This way, we can read the original file contents of the entire
    // library. We have to be careful, because doing so temporarily removes
    // the first 4096 bytes of the library from memory. And we don't want to
    // accidentally unmap code that we are executing. So, only use functions
    // that can be inlined.
    struct region *last = rb_entry_region(rb_first(&l->rb_region));

    void *start = first->start;
    l->image_size = last->offset + last->size;
    // It is possible to create a library that is only a single page in size.
    // In that case, we have to make sure that we artificially map one extra
    // page past the end of it, as our code relies on mremap() actually moving
    // the mapping.
    if (l->image_size < 8192)
      l->image_size = 8192;
    l->image = (char *)mremap(start, 4096, l->image_size, MREMAP_MAYMOVE);
    if (l->image_size == 8192 && l->image == start) {
      // We really mean it, when we say we want the memory to be moved.
      l->image = (char *)mremap(start, 4096, l->image_size, MREMAP_MAYMOVE);
      munmap((char *)start + 4096, 4096);
    }
    if (l->image == MAP_FAILED) {
      l->image = NULL;
    } else {
      void *addr = mmap(start,
                            4096,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            -1,
                            0);
      if (addr != start) {
        _nx_fatal_printf("library_buf_get_original: mmap failed\n");
      }
      for (int i = 4096 / sizeof(long); --i;
           ((long *)(start))[i] = ((long *)(l->image))[i])
        ;
    }
  }

  if (l->image) {
    _nx_debug_printf("library_buf_get_original: image %p\n", l->image);
    if (offset + len > l->image_size) {
      // It is quite likely that we initially did not map the entire file as
      // we did not know how large it is. So, if necessary, try to extend the
      // mapping.
      size_t size = (offset + len + 4095) & ~4095;
      char *tmp =
          (char *)(mremap(l->image, l->image_size, size, MREMAP_MAYMOVE));
      if (tmp != MAP_FAILED)
        l->image = tmp, l->image_size = size;
    }
    if (buf && offset + len <= l->image_size) {
      return (char *)memcpy(buf, l->image + offset, len);
    }
    return NULL;
  }
  _nx_debug_printf("library_buf_get_original: buf %p\n", buf);
  return buf ? library_buf_get(l, offset, buf, len) : NULL;
}

static const char* library_copy(struct library *lib, Elf_Addr offset) {
  if (!lib->valid)
    return "";

  _nx_debug_printf("library_copy: offset 0x%lx\n", offset);

  struct region *reg = rb_lower_bound_region(lib, offset);
  if (reg == NULL)
    return "";

  _nx_debug_printf("library_copy: lower bound 0x%lx (%p-%p)\n", reg->offset, reg->start, reg->end);

  offset -= reg->offset;
  const char *start = (char *)reg->start + offset;
  const char *stop = (char *)reg->end + offset;

  _nx_debug_printf("library_copy: range %p-%p\n", start, stop);

  char buf[4096] = {0};
  memcpy_fromlib(buf,
                 start,
                 (uintptr_t)(stop - start) >= sizeof(buf)
                     ? sizeof(buf) - 1
                     : (uintptr_t)(stop - start),
                 lib);
  for (start = buf, stop = buf; *stop != '\0'; ++stop);

  _nx_debug_printf("library_copy: updated range %p-%p\n", start, stop);

  if (stop <= start)
    return "";

  size_t len = stop - start + 1; // stop == \0 thus +1 to include NULL termination
  char *string = malloc(len);
  memcpy(string, start, len);

  assert(string[len-1] == '\0');
  return string;
}

static const char* library_copy_original(struct library *l, Elf_Addr offset) {
  if (!l->valid)
    goto empty;

  _nx_debug_printf("library_copy_original: offset 0x%lx\n", offset);

  // Make sure we actually have a mapping that we can access. If the string is
  // located at the end of the image, we might not yet have extended the
  // mapping sufficiently.
  if (!l->image || l->image_size <= offset)
    library_buf_get_original(l, offset, NULL, 1);

  if (l->image) {
    _nx_debug_printf("library_copy_original: image %p\n", l->image);
    if (offset < l->image_size) {
      char *start = l->image + offset;
      char *stop = start;
      while (stop < l->image + l->image_size && *stop) {
        ++stop;
        if (stop >= l->image + l->image_size)
          library_buf_get_original(l, stop - l->image, NULL, 1);
      }
      size_t len = stop - start;
      char *string = malloc(len + 1);
      _nx_debug_printf("library_copy_original: copy 0x%lx from %p to %p\n", len, start, string);
      *((char *)memcpy(string, start, len) + len) = '\0';
      return string;
    }
    goto empty;
  }
  return library_copy(l, offset);

empty:
  return "";
}

#define library_get(lib, off, val) \
  (typeof(val)) library_buf_get(lib, off, (char *)val, sizeof(typeof(*val)))

#define library_get_original(lib, off, val) \
  (typeof(val))                             \
      library_buf_get_original(lib, off, (char *)val, sizeof(typeof(*val)))

#define library_set(lib, off, val)                        \
  ({                                                      \
    struct region *__r = rb_lower_bound_region(lib, off); \
    if (__r) {                                            \
      off -= __r->offset;                                 \
      if (off <= __r.size - sizeof(typeof(*val)))         \
        *(typeof(val))((char *)__r->start + off) = *val;  \
    }                                                     \
  })

static void library_make_writable(struct library *l, bool state) {
  struct region *reg;
  struct region *n;

  rbtree_postorder_for_each_entry_safe(reg, n, &l->rb_region, rb_region) {
    mprotect(reg->start, reg->size, reg->perms | (state ? PROT_WRITE : 0));
  }
}

static inline bool is_safe_insn(unsigned short insn) {
  /* Check if the instruction has no unexpected side-effects. If so, it can
     be safely relocated from the function that we are patching into the
     out-of-line scratch space that we are setting up. This is often necessary
     to make room for the JMP into the scratch space. */
  return ((insn & 0x7) < 0x6 &&
          (insn & 0xF0) < 0x40
              /* ADD, OR, ADC, SBB, AND, SUB, XOR, CMP */) ||
         insn == 0x63 /* MOVSXD */ ||
         (insn >= 0x80 && insn <= 0x8E /* ADD, OR, ADC,
         SBB, AND, SUB, XOR, CMP, TEST, XCHG, MOV, LEA */) ||
         (insn == 0x90) || /* NOP */
         (insn >= 0xA0 && insn <= 0xA9) /* MOV, TEST */ ||
         (insn >= 0xB0 && insn <= 0xBF /* MOV */) ||
         (insn >= 0xC0 && insn <= 0xC1) || /* Bit Shift */
         (insn >= 0xD0 && insn <= 0xD3) || /* Bit Shift */
         (insn >= 0xC6 && insn <= 0xC7 /* MOV */) ||
         (insn == 0xF7) /* TEST, NOT, NEG, MUL, IMUL, DIV, IDIV */ ||
         (insn >= 0xF19 && insn <= 0xF1F) /* long NOP */;
}

static char *alloc_scratch_space(int fd,
                                 char *addr,
                                 int needed,
                                 char **extra_space,
                                 int *extra_len,
                                 bool near) {
  if (needed > *extra_len || (near &&
      labs(*extra_space - (char *)(addr)) > (1536 << 20))) {
    // Start a new scratch page and mark any previous page as write-protected
    if (*extra_space)
      mprotect(*extra_space, 4096, PROT_READ | PROT_EXEC);
    // Our new scratch space is initially executable and writable.
    *extra_len = 4096;
    *extra_space = maps_alloc_near(
        fd, addr, *extra_len, PROT_READ | PROT_WRITE | PROT_EXEC, near);
    _nx_debug_printf("alloc_scratch_space: mapped %x at %p (near %p)\n",
        *extra_len, *extra_space, addr);
  }
  if (*extra_space) {
    *extra_len -= needed;
    return *extra_space + *extra_len;
  }
  _nx_fatal_printf("No space left to allocate scratch space");
}

static void patch_syscalls_in_func(struct library *lib,
                                           char *start,
                                           char *end,
                                           char **extra_space,
                                           int *extra_len,
                                           bool loader) {
  struct rb_root branch_targets = RB_ROOT;

  _nx_debug_printf("patch_syscalls_in_func: function %p-%p\n", start, end);

  {
    // Count how many targets we'll need
    unsigned long total = 0;
    for (char *ptr = start; ptr < end;) {
      unsigned short insn = next_inst(
          (const char **)&ptr, __WORDSIZE == 64, NULL, NULL, NULL, NULL, NULL);
      if ((insn >= 0x70 && insn <= 0x7F) /* Jcc */ || insn == 0xEB /* JMP */ ||
          insn == 0xE8 /* CALL */ || insn == 0xE9 /* JMP */ ||
          (insn >= 0x0F80 && insn <= 0x0F8F) /* Jcc */) {
        total += 1;
      }
    }

    // Allocate all the memory we'll need in one go
    struct branch_target *target = malloc(total*sizeof(*target));

    // Lookup branch targets dynamically.
    for (char *ptr = start; ptr < end;) {
      unsigned short insn = next_inst(
          (const char **)&ptr, __WORDSIZE == 64, NULL, NULL, NULL, NULL, NULL);
      char *addr;
      if ((insn >= 0x70 && insn <= 0x7F) /* Jcc */ || insn == 0xEB /* JMP */) {
        addr = ptr + ((signed char *)(ptr))[-1];
      } else if (insn == 0xE8 /* CALL */ || insn == 0xE9 /* JMP */ ||
          (insn >= 0x0F80 && insn <= 0x0F8F) /* Jcc */) {
        addr = ptr + ((int *)(ptr))[-1];
      } else
        continue;

      target->addr = addr;
      rb_insert_target(&branch_targets, addr, &target->rb_target);
      target += 1;
    }
  }

  struct code {
    char *addr;
    int len;
    unsigned short insn;
    bool is_ip_relative;
  } code[5] = {{0}};

  int i = 0;
  for (char *ptr = start; ptr < end;) {
    // Keep a ring-buffer of the last few instruction in order to find the
    // correct place to patch the code.
    char *mod_rm;
    code[i].addr = ptr;
    code[i].insn =
        next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
    code[i].len = ptr - code[i].addr;
    code[i].is_ip_relative =
        mod_rm && (*mod_rm & 0xC7) == 0x5;

    // Whenever we find a system call, we patch it with a jump to out-of-line
    // code that redirects to our system call entrypoint.
#if defined(__NX_INTERCEPT_RDTSC) || defined(SBR_DEBUG)
    bool is_rdtsc = false;
#endif
    if (code[i].insn == 0x0F05 /* SYSCALL */
#ifdef __NX_INTERCEPT_RDTSC
        || ((is_rdtsc = (code[i].insn == 0x0F31)) /* RDTSC */ && !loader)
#endif
       ) {

      // Found a system call. Search backwards to figure out how to redirect
      // the code. We will need to overwrite a couple of instructions and,
      // of course, move these instructions somewhere else.
      int start_idx = i;
      int length = code[i].len;
      for (int j = i; (j = (j + (sizeof(code) / sizeof(struct code)) - 1) %
                           (sizeof(code) / sizeof(struct code))) != i;) {
        struct branch_target *target =
            rb_upper_bound_target(&branch_targets, code[j].addr);
        if (target && target->addr < ptr) {
          // Found a branch pointing to somewhere past our instruction. This
          // instruction cannot be moved safely. Leave it in place.
          break;
        }
        if (code[j].addr && !code[j].is_ip_relative &&
            is_safe_insn(code[j].insn)) {
          // These are all benign instructions with no side-effects and no
          // dependency on the program counter. We should be able to safely
          // relocate them.
          start_idx = j;
          length = ptr - code[start_idx].addr;
        } else {
          break;
        }
      }
// Search forward past the system call, too. Sometimes, we can only find
// relocatable instructions following the system call.
      char *next = ptr;
      for (int j = i;
           next < end && (j = (j + 1) % (sizeof(code) / sizeof(struct code))) !=
                             start_idx;) {
        struct branch_target *target =
            rb_lower_bound_target(&branch_targets, next);
        if (target && target->addr == next) {
          // Found branch target pointing to our instruction
          break;
        }
        char *tmp_rm;
        code[j].addr = next;
        code[j].insn = next_inst(
            (const char **)&next, __WORDSIZE == 64, 0, 0, &tmp_rm, 0, 0);
        code[j].len = next - code[j].addr;
        code[j].is_ip_relative = tmp_rm && (*tmp_rm & 0xC7) == 0x5;
        if (!code[j].is_ip_relative && is_safe_insn(code[j].insn)) {
          length = next - code[start_idx].addr;
        } else {
          break;
        }
      }
      // We now know, how many instructions neighboring the system call we can
      // safely overwrite. On x86-32 we need six bytes, and on x86-64 We need
      // five bytes to insert a JMPQ and a 32bit address. We then jump to a
      // code fragment that safely forwards to our system call entrypoint.
      //
      // On x86-64, this is complicated by the fact that the API allows up to
      // 128 bytes of red-zones below the current stack pointer. So, we cannot
      // write to the stack until we have adjusted the stack pointer.
      //
      // On both x86-32 and x86-64 we take care to leave the stack unchanged
      // while we are executing the preamble and postamble. This allows us to
      // treat instructions that reference %esp/%rsp as safe for relocation.
      //
      // In particular, this means that on x86-32 we cannot use CALL, but have
      // to use a PUSH/RET combination to change the instruction pointer. On
      // x86-64, we can instead use a 32bit JMPQ.
      //
      // .. .. .. .. ; any leading instructions copied from original code
      // 48 81 EC 80 00 00 00        SUB  $0x80, %rsp
      // 50                          PUSH %rax
      // 48 8D 05 .. .. .. ..        LEA  ...(%rip), %rax
      // 50                          PUSH %rax
      // 48 B8 .. .. .. ..           MOV  $syscall_enter_with_frame, %rax
      // .. .. .. ..
      // 50                          PUSH %rax
      // 48 8D 05 06 00 00 00        LEA  6(%rip), %rax
      // 48 87 44 24 10              XCHG %rax, 16(%rsp)
      // C3                          RETQ
      // 48 81 C4 80 00 00 00        ADD  $0x80, %rsp
      // .. .. .. .. ; any trailing instructions copied from original code
      // E9 .. .. .. ..              JMPQ ...
      //
      // Total: 52 bytes + any bytes that were copied
      //
      // On x86-32, the stack is available and we can do:
      //
      // TODO(markus): Try to maintain frame pointers on x86-32
      //
      // .. .. .. .. ; any leading instructions copied from original code
      // 68 .. .. .. ..              PUSH . + 11
      // 68 .. .. .. ..              PUSH return_addr
      // 68 .. .. .. ..              PUSH $syscall_enter_with_frame
      // C3                          RET
      // .. .. .. .. ; any trailing instructions copied from original code
      // 68 .. .. .. ..              PUSH return_addr
      // C3                          RET
      //
      // Total: 22 bytes + any bytes that were copied
      //
      // For indirect jumps from the VDSO to the VSyscall page, we instead
      // replace the following code (this is only necessary on x86-64). This
      // time, we don't have to worry about red zones:
      //
      // .. .. .. .. ; any leading instructions copied from original code
      // E8 00 00 00 00              CALL .
      // 48 83 04 24 ..              ADDQ $.., (%rsp)
      // FF .. .. .. .. ..           PUSH ..  ; from original CALL instruction
      // 48 81 3C 24 00 00 00 FF     CMPQ $0xFFFFFFFFFF000000, 0(%rsp)
      // 72 10                       JB   . + 16
      // 81 2C 24 .. .. .. ..        SUBL ..., 0(%rsp)
      // C7 44 24 04 00 00 00 00     MOVL $0, 4(%rsp)
      // C3                          RETQ
      // 48 87 04 24                 XCHG %rax,(%rsp)
      // 48 89 44 24 08              MOV  %rax, 8(%rsp)
      // 58                          POP  %rax
      // C3                          RETQ
      // .. .. .. .. ; any trailing instructions copied from original code
      // E9 .. .. .. ..              JMPQ ...
      //
      // Total: 52 bytes + any bytes that were copied

      if (length < (__WORDSIZE == 32 ? 6 : 5)) {
        // If we cannot figure out any other way to intercept this syscall/RDTSC,
        // we replace it with an illegal instruction. This causes a SIGILL which we then
        // handle in the signal handler. That's a lot slower than rewriting the
        // instruction with a jump, but it should only happen very rarely.
#ifdef __NX_INTERCEPT_RDTSC
        if (is_rdtsc) {
          memcpy(code[i].addr, "\x0F\x0B" /* UD2 */, 2);
          goto replaced;
        }
        else
#endif
        {
          memcpy(code[i].addr, "\x0F\xFF" /* UD0 */, 2);
          goto replaced;
        }
      }
      int needed = (__WORDSIZE == 32 ? 6 : 5) - code[i].len;
      int first = i;
      while (needed > 0 && first != start_idx) {
        first = (first + (sizeof(code) / sizeof(struct code)) - 1) %
                (sizeof(code) / sizeof(struct code));
        needed -= code[first].len;
      }
      int second = i;
      while (needed > 0) {
        second = (second + 1) % (sizeof(code) / sizeof(struct code));
        needed -= code[second].len;
      }
      int preamble = code[i].addr - code[first].addr;
      int postamble =
          code[second].addr + code[second].len - code[i].addr - code[i].len;

      // The following is all the code that construct the various bits of
      // assembly code.
      needed = 52 + preamble + postamble;

      // Allocate scratch space and copy the preamble of code that was moved
      // from the function that we are patching.
      char *dest = alloc_scratch_space(
          lib->maps->fd, code[first].addr, needed, extra_space, extra_len, true);
      memcpy(dest, code[first].addr, preamble);

      // For jumps from the VDSO to the VSyscalls we sometimes allow exactly
      // one IP relative instruction in the preamble.
      if (code[first].is_ip_relative) {
        *(int *)(dest + (code[i].addr - code[first].addr) - 4) -=
            dest - code[first].addr;
      }

      // Copy the static body of the assembly code.
      memcpy(
          dest + preamble,
              "\x48\x81\xEC\x80\x00\x00\x00" // SUB  $0x80, %rsp
              "\x50"                         // PUSH %rax
              "\x48\x8D\x05\x00\x00\x00\x00" // LEA  ...(%rip), %rax
              "\x50"                         // PUSH %rax
              "\x48\xB8\x00\x00\x00\x00\x00" // MOV $entrypoint,
              "\x00\x00\x00"                 //     %rax
              "\x50"                         // PUSH %rax
              "\x48\x8D\x05\x06\x00\x00\x00" // LEA  6(%rip), %rax
              "\x48\x87\x44\x24\x10"         // XCHG %rax, 16(%rsp)
              "\xC3"                         // RETQ
              "\x48\x81\xC4\x80\x00\x00",    // ADD  $0x80, %rsp
          47
          );

      // Copy the postamble that was moved from the function that we are
      // patching.
      memcpy(dest + preamble + 47,
             code[i].addr + code[i].len,
             postamble);

      // Patch up the various computed values
      int post = preamble + 47 + postamble;
      dest[post] = '\xE9';  // JMPQ
      *(int *)(dest + post + 1) =
          (code[second].addr + code[second].len) - (dest + post + 5);
      *(int *)(dest + preamble + 11) =
          (code[second].addr + code[second].len) - (dest + preamble + 15);
      void* entrypoint;

      if (loader)
        entrypoint = handle_syscall_loader;
#ifdef __NX_INTERCEPT_RDTSC
      else if (is_rdtsc) {
        entrypoint = rdtsc_entrypoint;
      }
#endif
      else
        entrypoint = handle_syscall;
      *(void **)(dest + preamble + 18) = entrypoint;
      // Pad unused space in the original function with NOPs
      memset(code[first].addr,
             0x90 /* NOP */,
             code[second].addr + code[second].len - code[first].addr);

      // Replace the system call with an unconditional jump to our new code.
      *code[first].addr = '\xE9';  // JMPQ
      *(int *)(code[first].addr + 1) = dest - (code[first].addr + 5);
      _nx_debug_printf("patched %s at %p (scratch space at %p)\n",
                  (is_rdtsc ? "rdtsc" : "syscall"), code[i].addr, dest);
    }
  replaced:
    i = (i + 1) % (sizeof(code) / sizeof(struct code));
  }
}

static inline struct rb_root *lookup_branch_targets(char *start, char *end) {
  struct rb_root *branch_targets;

  branch_targets = (struct rb_root *)malloc(sizeof(*branch_targets));
  assert(branch_targets != NULL);
  *branch_targets = RB_ROOT;

  // Lookup branch targets dynamically.
  for (char *ptr = start; ptr < end;) {
    unsigned short insn = next_inst(
        (const char **)&ptr, __WORDSIZE == 64, NULL, NULL, NULL, NULL, NULL);
    char *addr;
    if ((insn >= 0x70 && insn <= 0x7F) /* Jcc */ || insn == 0xEB /* JMP */) {
      addr = ptr + ((signed char *)(ptr))[-1];
    } else if (insn == 0xE8 /* CALL */ || insn == 0xE9 /* JMP */ ||
               (insn >= 0x0F80 && insn <= 0x0F8F) /* Jcc */) {
      addr = ptr + ((int *)(ptr))[-1];
    } else {
      continue;
    }

    struct branch_target *target = malloc(sizeof(*target));
    target->addr = addr;
    rb_insert_target(branch_targets, addr, &target->rb_target);
  }

  return branch_targets;
}

struct s_code {
  char *addr;
  int len;
  unsigned short insn;
  bool is_ip_relative;
};

#if defined(USE_ABS_JMP_DETOUR)
#define JUMP_SIZE 12 // 10 bytes to load target address into register + 2 bytes to jump
#else
#define JUMP_SIZE 5 // 1 byte for the opcode + 4 bytes for the 32-bit displacement
#endif

static const char DETOUR_ASM [] =
    // after rewriting, the detoured function jumps to here
    "\x48\x83\xEC\x08"              // SUB  $0x8, %rsp          # stack alignment
    "\x49\xBB\x00\x00\x00\x00\x00"  // MOVABS $handler, %r11    # load handler address
    "\x00\x00\x00"
    "\x41\xFF\xD3"                  // CALLQ *%r11              # call handler
    "\x48\x83\xC4\x08"              // ADD  $0x8, %rsp          # stack alignment
    "\xC3";                         // RETQ                     # return to detoured function (except for __libc_start_main)
    // the postamble (i.e. first instructions of detoured function relocated to accommodate the jump) comes here
    // then comes the jump back to detoured function after relocated instructions

static const size_t DETOUR_ASM_SIZE = sizeof(DETOUR_ASM) - 1;
static const size_t HANDLER_OFFSET = 6;

/**
 * Compute the amount of space needed to accommodate relocated instructions
 *
 * @param[in]  code              relocatable instructions
 * @param[out] needed            total amount of bytes to write
 * @param[out] postamble         amount of bytes to relocate
 * @param[out] second            first instruction not to be relocated
 * @param[in]  detour_asm_size   size of static ASM body
 *
 */
static inline void needed_space(const struct s_code * code, int * needed, int * postamble, int * second, size_t detour_asm_size) {
  int additional_bytes_to_relocate = (__WORDSIZE == 32 ? 6 : JUMP_SIZE) - code[0].len;
  *second = 0;
  while (additional_bytes_to_relocate > 0) {
    *second = (*second + 1) % JUMP_SIZE;
    additional_bytes_to_relocate -= code[*second].len;
  }
  *postamble = (code[*second].addr + code[*second].len) - code[0].addr;

  // The following is all the code that construct the various bits of
  // assembly code.
  *needed = detour_asm_size + *postamble + JUMP_SIZE;
}

static inline void copy_postamble(void * dest, struct s_code code[], int second) {
  // Copy each instruction, one by one,
  // fixing eventual instructions that use the RIP register
  void * curr = dest;
  for (int insn = 0 ; insn <= second ; insn++) {
    if (code[insn].is_ip_relative
        || code[insn].insn == 0x0f84 /* JE */) {
      bool has_prefix;
      char *rex_ptr;
      char *mod_rm_ptr;
      char *sib_ptr;
      switch (code[insn].insn) {
        case 0x83: // CMP
          {
          // Instruction format:
          //         83 3D XX XX XX XX XX
          //         -- -- ----------- --
          // addr +  0  1  2           6
          //         |  |  |            -> 8 bit immediate
          //         |  |   -> 32 bit RIP displacement
          //         |   -> Mod R/M byte
          //          -> Opcode


          // Compute value the RIP would hold at runtime
          char* rip = code[insn].addr;
          // Get the RIP-relative displacement in the instruction
          int disp = *(int*)(rip+2);
          // Compute displacement from the new code to the original instruction
          long ldisp = ((long)rip - (long)curr);
          // Displacement larger than 32 bits?  Not supported yet
          if (ldisp > (long)UINT32_MAX || (ldisp*-1) > (long)UINT32_MAX)
            _nx_fatal_printf("vDSO RIP MOV requires unsupported 64 bit displacement");

          // Emit instruction
          memcpy(curr, code[insn].addr, code[insn].len); // CMP [rip+0xXXXX]      , 0xXX
          *(int*)(((char*)curr)+2) = (int)ldisp + disp;  // CMP [rip+0xXXXX+disp] , 0xXX
          curr += code[insn].len;
          break;
          }
        case 0x8B: // REX.W MOV
          {
          // Instruction format:
          //         48 8B X5 XX XX XX XX
          //         -- -- -- -----------
          // addr +  0  1  2  3
          //         |  |  |   -> 32 bit RIP displacement
          //         |  |   -> Mod R/M byte ending in 0x5
          //         |   -> Opcode
          //          -> Preffix REX.W

          //         8B X5 XX XX XX XX
          //         -- -- ------------
          // addr +  0  1  2
          //         |  |  |
          //         |  |   -> 32 bit RIP displacement
          //         |   -> Mod R/M byte ending in 0x5
          //          -> Opcode


          // Decode instruction
          const char * code_ptr = code[insn].addr;
          next_inst(
            &code_ptr,
            __WORDSIZE == 64,
            &has_prefix,
            &rex_ptr,
            &mod_rm_ptr,
            &sib_ptr,
            NULL
          );
          if (has_prefix && *rex_ptr == (char)0x48) {
            // Compute value the RIP would hold at runtime
            char* rip = code[insn].addr;
            // Get the RIP-relative displacement in the instruction
            int disp = *(int*)(rip+3);
            // Compute displacement from the new code to the original instruction
            long ldisp = ((long)rip - (long)curr);
            // Displacement larger than 32 bits?  Not supported yet
            if (ldisp > (long)UINT32_MAX || (ldisp*-1) > (long)UINT32_MAX)
              _nx_fatal_printf("vDSO RIP MOV requires unsupported 64 bit displacement");

            // Emit instruction
            memcpy(
                curr,
                "\x48\x8B\x00\x00\x00\x00\x00",             // REX.W MOV ... , [...]
                7);
            *(((char*)curr)+2) = *mod_rm_ptr;             // REX.W MOV reg , [rip+...]
            *(int*)(((char*)curr)+3) = (int)ldisp + disp; // REX.W MOV reg , [rip+disp]
            curr += 7;
          } else {
            // Compute value the RIP would hold at runtime
            char* rip = code[insn].addr;
            // Get the RIP-relative displacement in the instruction
            int disp = *(int*)(rip+2);
            // Compute displacement from the new code to the original instruction
            long ldisp = ((long)rip - (long)curr);
            // Displacement larger than 32 bits?  Not supported yet
            if (ldisp > (long)UINT32_MAX || (ldisp*-1) > (long)UINT32_MAX)
              _nx_fatal_printf("vDSO RIP MOV requires unsupported 64 bit displacement");

            // Emit instruction
            memcpy(
                curr,
                "\x8B\x00\x00\x00\x00\x00",             // MOV ... , [...]
                6);
            *(((char*)curr)+1) = *mod_rm_ptr;             // REX.W MOV reg , [rip+...]
            *(int*)(((char*)curr)+2) = (int)ldisp + disp; // REX.W MOV reg , [rip+disp]
            curr += 6;
          }

          /* ******************************************************************
          // The following is commented out to provide some guidance for future
          // implementations of instructions not currently supported:
          // Get register from Mod R/M byte
          char reg_w = (char) (*mod_rm_ptr & 0b00111000);
          // Compute new Mod R/M byte
          char mod_rm = (char) 0b00000100 | reg_w;
          ****************************************************************** */

          break;
          }
        case 0x8D: // LEA
          {
          //         8B X5 XX XX XX XX XX
          //         -- -- -- ------------
          // addr +  0  1  2  3
          //         |  |     |
          //         |  |      -> 32 bit RIP displacement
          //         |   -> Mod R/M byte ending in 0x5
          //          -> Opcode


          // Decode instruction
          const char * code_ptr = code[insn].addr;
          next_inst(
            &code_ptr,
            __WORDSIZE == 64,
            &has_prefix,
            &rex_ptr,
            &mod_rm_ptr,
            &sib_ptr,
            NULL
          );

          // Compute value the RIP would hold at runtime
          char* rip = code[insn].addr;
          // Get the RIP-relative displacement in the instruction
          int disp = *(int*)(rip+3);
          // Compute displacement from the new code to the original instruction
          long ldisp = ((long)rip - (long)curr);
          ldisp += disp;
          // Displacement larger than 32 bits?  Not supported yet
          if (ldisp > (long)UINT32_MAX || (ldisp*-1) > (long)UINT32_MAX)
            _nx_fatal_printf("vDSO RIP MOV requires unsupported 64 bit displacement");

          // Emit instruction
          memcpy(
              curr,
              rip,             // LEA ... , [...]
              7);
          *(int*)(((char*)curr)+3) = (int)ldisp; // LEA reg , [rip+disp]
          curr += 7;

          /* ******************************************************************
          // The following is commented out to provide some guidance for future
          // implementations of instructions not currently supported:
          // Get register from Mod R/M byte
          char reg_w = (char) (*mod_rm_ptr & 0b00111000);
          // Compute new Mod R/M byte
          char mod_rm = (char) 0b00000100 | reg_w;
          ****************************************************************** */

          break;
          }
        case 0x0F84: // JE
          {
          //         0F 84 XX XX XX XX
          //         ----- -----------
          // addr +  0  1  2  3  4  5
          //         |     |
          //         |      -> 32 bit displacement
          //          -> Opcode


          // Decode instruction
          const char * code_ptr = code[insn].addr;
          next_inst(
            &code_ptr,
            __WORDSIZE == 64,
            &has_prefix,
            &rex_ptr,
            &mod_rm_ptr,
            &sib_ptr,
            NULL
          );

          // Compute value the RIP would hold at runtime
          char* rip = code[insn].addr;
          // Get the RIP-relative displacement in the instruction
          int disp = *(int*)(rip+2);
          // Compute displacement from the new code to the original instruction
          long ldisp = ((long)rip - (long)curr);
          ldisp += disp;
          // Displacement larger than 32 bits?  Not supported yet
          if (ldisp > (long)UINT32_MAX || (ldisp*-1) > (long)UINT32_MAX)
            _nx_fatal_printf("vDSO RIP MOV requires unsupported 64 bit displacement");

          // Emit instruction
          memcpy(
              curr,
              rip,             // JE ...
              6);
          *(int*)(((char*)curr)+2) = (int)ldisp; // JE rel32
          curr += 6;

          break;
          }
        default:
          _nx_fatal_printf("vDSO RIP relative instruction not supported");
      }
    } else {
      memcpy(curr, code[insn].addr, code[insn].len);
      curr += code[insn].len;
    }
  }
}

static inline void detour_func(struct library *lib,
                                        char *start,
                                        char *end,
                                        int syscall_no,
                                        char **extra_space,
                                        int *extra_len) {
  void *trampoline_addr = NULL;
  struct rb_root *branch_targets;
  struct s_code code[JUMP_SIZE] = {{0}};

  branch_targets = lookup_branch_targets(start, end);

  // Keep a ring-buffer of the last few instruction in order to find the correct
  // place to patch the code.
  char *mod_rm;
  char *ptr = start;
  code[0].addr = ptr;
  code[0].insn =
      next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
  code[0].len = ptr - code[0].addr;
  code[0].is_ip_relative =
      mod_rm && (*mod_rm & 0xC7) == 0x5;
  int length = code[0].len;
  char *next = ptr;
  for (size_t i = 1; next < end && i < JUMP_SIZE; i++) {
    struct branch_target *target = rb_lower_bound_target(branch_targets, next);
    if (target && target->addr == next) {
      // Found branch target pointing to our instruction.
      break;
    }
    char *tmp_rm;
    code[i].addr = next;
    code[i].insn =
        next_inst((const char **)&next, __WORDSIZE == 64, 0, 0, &tmp_rm, 0, 0);
    code[i].len = next - code[i].addr;
    code[i].is_ip_relative =
        tmp_rm && (*tmp_rm & 0xC7) == 0x5;
    if (is_safe_insn(code[i].insn) ||
         (code[i].insn >= 0x50 && code[i].insn <= 0x57) /* PUSH */ ||
         (code[i].insn == 0x6A) /* PUSH */ ||
         (code[i].insn == 0x68) /* PUSH */) {
      length = next - code[0].addr;
    } else {
      break;
    }
  }

  if (length < (__WORDSIZE == 32 ? 6 : JUMP_SIZE)) {
    _nx_fatal_printf("Cannot intercept system call");
  }

  int needed, postamble, second;
  needed_space(code, &needed, &postamble, &second,
#if defined(USE_ABS_JMP_DETOUR)
		       70
#else
		       67
#endif
		       );

  // Allocate scratch space and copy the preamble of code that was moved
  // from the function that we are patching.
  char *dest = alloc_scratch_space(
      lib->maps->fd, code[0].addr, needed, extra_space, extra_len,
#if defined(USE_ABS_JMP_DETOUR)
      false);
#else
      true);
#endif
#if defined(USE_ABS_JMP_DETOUR)
  trampoline_addr = dest + 70;
#else
  trampoline_addr = dest + 67;
#endif

  void *plugin_handler;

  if (vdso_callback)
    plugin_handler = vdso_callback(syscall_no, trampoline_addr);
  else
    plugin_handler = NULL;

  // Copy the static body of the assembly code.
  memcpy(dest,
         "\xb8\x00\x00\x00\x00"          // MOV $syscall_no, %eax
         "\x48\x81\xEC\x80\x00\x00\x00"  // SUB  $0x80, %rsp
         "\x41\x57"                      // PUSH %r15
         "\x49\xBF\x00\x00\x00\x00\x00"  // MOV $plugin_handler
         "\x00\x00\x00"                  //     %r15
         "\x50"                          // PUSH %rax
#if defined(USE_ABS_JMP_DETOUR)
         "\x48\xB8\x00\x00\x00\x00\x00"  // MOV ...,
         "\x00\x00\x00"                  //     %rax
#else
         "\x48\x8D\x05\x00\x00\x00\x00"  // LEA $fake_ret_addr(%rip), %rax
#endif
         "\x50"                          // PUSH %rax
         "\x48\xB8\x00\x00\x00\x00\x00"  // MOV $handle_vdso,
         "\x00\x00\x00"                  //     %rax
         "\x50"                          // PUSH %rax
         "\x48\x8D\x05\x06\x00\x00\x00"  // LEA  6(%rip), %rax
         "\x48\x87\x44\x24\x10"          // XCHG %rax, 16(%rsp)
         "\xC3"                          // RETQ
         "\x41\x5f"                      // POP %r15
         "\x48\x81\xC4\x80\x00\x00\x00"  // ADD  $0x80, %rsp
         "\xC3",                         // RETQ
#if defined(USE_ABS_JMP_DETOUR)
         70
#else
         67
#endif
         );

  // Copy the postamble that was moved from the function that we are
  // patching.
  copy_postamble(dest +
#if defined(USE_ABS_JMP_DETOUR)
             70,
#else
             67,
#endif
         code,
         second);

  // Patch up the various computed values
#if defined(USE_ABS_JMP_DETOUR)
  int post = 70 + postamble;
  memcpy(dest + post,
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
         "\xFF\xE0",                    // JMP *%rax
         CODE_LENGTH);
  *(void **)(dest + post + 2) =
      (void *)(code[second].addr + code[second].len);
#else
  int post = 67 + postamble;
  dest[post] = '\xE9';  // JMPQ
  *(int *)(dest + post + 1) =
      (code[second].addr + code[second].len) - (dest + post + JUMP_SIZE);
#endif
  *(int *)(dest + 1) = syscall_no;
  *(void **)(dest + 16) = plugin_handler;
#if defined(USE_ABS_JMP_DETOUR)
  *(void **)(dest + 27) = (void *)code[second].addr;
  *(void **)(dest + 38) = handle_vdso;
#else
  ptrdiff_t fake_ret_addr = (code[second].addr + code[second].len) - (dest + 32);
  *(int *)(dest + 28) = fake_ret_addr;
  *(void **)(dest + 35) = handle_vdso;
#endif

  // Pad unused space in the original function with NOPs
  memset(code[0].addr,
         0x90 /* NOP */,
         (code[second].addr + code[second].len) - code[0].addr);

  // Replace the system call with an unconditional jump to our new code.
#if defined(USE_ABS_JMP_DETOUR)
  memcpy(code[0].addr,
         //"\x48\xA1\x00\x00\x00\x00\x00" // MOV ...,
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
         "\xFF\xE0",                    // JMP *%rax
         JUMP_SIZE);
  *(void **)(code[0].addr + 2) = (void *)(dest);
#else
  *code[0].addr = '\xE9';  // JMPQ
  *(int *)(code[0].addr + 1) = dest - (code[0].addr + JUMP_SIZE);
#endif

}


static void api_detour_func(struct library *lib,
                                        char *start,
                                        char *end,
                                           sbr_icept_callback_fn callback,
                                        char **extra_space,
                                        int *extra_len) {
  void *trampoline_addr = NULL;
  struct rb_root *branch_targets;
  struct s_code code[JUMP_SIZE] = {{0}};

  branch_targets = lookup_branch_targets(start, end);

  // Keep a ring-buffer of the last few instruction in order to find the correct
  // place to patch the code.
  char *mod_rm;
  char *ptr = start;
  code[0].addr = ptr;
  code[0].insn =
      next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
  code[0].len = ptr - code[0].addr;
  code[0].is_ip_relative =
      mod_rm && (*mod_rm & 0xC7) == 0x5;
  int length = code[0].len;
  char *next = ptr;
  for (size_t i = 1; next < end && i < JUMP_SIZE; i++) {
    struct branch_target *target = rb_lower_bound_target(branch_targets, next);
    if (target && target->addr == next) {
      // Found branch target pointing to our instruction.
      break;
    }
    char *tmp_rm;
    code[i].addr = next;
    code[i].insn =
        next_inst((const char **)&next, __WORDSIZE == 64, 0, 0, &tmp_rm, 0, 0);
    code[i].len = next - code[i].addr;
    code[i].is_ip_relative =
        tmp_rm && (*tmp_rm & 0xC7) == 0x5;
    if (is_safe_insn(code[i].insn) ||
         (code[i].insn == 0x0F84) /* JE rel32 */ ||
         (code[i].insn >= 0x50 && code[i].insn <= 0x57) /* PUSH */ ||
         (code[i].insn == 0x6A) /* PUSH */ ||
         (code[i].insn == 0x68) /* PUSH */) {
      length = next - code[0].addr;
    } else {
      break;
    }
  }

  if (length < (__WORDSIZE == 32 ? 6 : JUMP_SIZE)) {
    _nx_fatal_printf("Cannot intercept system call");
  }

  int needed, postamble, second;
  needed_space(code, &needed, &postamble, &second, DETOUR_ASM_SIZE);

  // Allocate scratch space and copy the preamble of code that was moved
  // from the function that we are patching.
  char *dest = alloc_scratch_space(
      lib->maps->fd, code[0].addr, needed, extra_space, extra_len,
#if defined(USE_ABS_JMP_DETOUR)
      false);
#else
      true);
#endif

  memcpy(dest, DETOUR_ASM, DETOUR_ASM_SIZE);

  // Copy the postamble that was moved from the function that we are
  // patching.
  copy_postamble(dest + DETOUR_ASM_SIZE,
         code,
         second);

  // Patch up the various computed values
  trampoline_addr = dest + DETOUR_ASM_SIZE;
  void *handler = callback(trampoline_addr);
  assert(handler);

  int post = DETOUR_ASM_SIZE + postamble;
  dest[post] = '\xE9';  // JMPQ
  *(int *)(dest + post + 1) =
      (code[second].addr + code[second].len) - (dest + post + JUMP_SIZE);
  *(void **)(dest + HANDLER_OFFSET) = handler;
  // Pad unused space in the original function with NOPs
  memset(code[0].addr,
         0x90 /* NOP */,
         (code[second].addr + code[second].len) - code[0].addr);

// Replace the system call with an unconditional jump to our new code.
#if defined(USE_ABS_JMP_DETOUR)
  memcpy(code[0].addr,
         //"\x48\xA1\x00\x00\x00\x00\x00" // MOV ...,
         "\x48\xB8\x00\x00\x00\x00\x00" // MOV ...,
         "\x00\x00\x00"                 //     %rax
         "\xFF\xE0",                    // JMP *%rax
         JUMP_SIZE);
  *(void **)(code[0].addr + 2) = (void *)(dest);
#else
  *code[0].addr = '\xE9';  // JMPQ
  *(int *)(code[0].addr + 1) = dest - (code[0].addr + JUMP_SIZE);
#endif

}

static void patch_vdso(struct library *lib) {
  _nx_debug_printf("patch_vdso: %s\n", lib->pathname);

  int extra_len = 0;
  char *extra_space = NULL;

  struct section *scn = section_find(lib->section_hash, ".text");
  if (!scn)
    _nx_fatal_printf("no vdso .text section");
  _nx_debug_printf("vdso .text section %p\n", scn);

  const Elf_Shdr *shdr = &scn->shdr;
  char *addr = (char *)(shdr->sh_addr + lib->asr_offset);
  size_t size = round_up(shdr->sh_size, 0x1000);

  if (mprotect((void *)((long)addr & ~0xFFF), size,
                   PROT_READ | PROT_WRITE | PROT_EXEC)) {
    _nx_fatal_printf("mprotect failed\n");
  }
  _nx_debug_printf("mprotect done\n");

  struct symbol *sym = symbol_find(lib->symbol_hash, "__vdso_getcpu");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib,
        lib->asr_offset + sym->sym.st_value,
        lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
        __NR_getcpu,
        &extra_space,
        &extra_len);
  }
  sym = symbol_find(lib->symbol_hash, "__vdso_time");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib,
        lib->asr_offset + sym->sym.st_value,
        lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
        __NR_time,
        &extra_space,
        &extra_len);
  }
  sym = symbol_find(lib->symbol_hash, "__vdso_gettimeofday");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib,
        lib->asr_offset + sym->sym.st_value,
        lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
        __NR_gettimeofday,
        &extra_space,
        &extra_len);
  }
  sym = symbol_find(lib->symbol_hash, "__vdso_clock_gettime");
  if (sym != NULL && (void *)sym->sym.st_value != NULL) {
    detour_func(lib,
        lib->asr_offset + sym->sym.st_value,
        lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
        __NR_clock_gettime,
        &extra_space,
        &extra_len);
  }

  if (extra_space != NULL) {
    // Mark our scratch space as write-protected and executable.
    mprotect(extra_space, 0x1000, PROT_READ | PROT_EXEC);
  }
}

static void patch_syscalls_in_range(struct library *lib,
                                     char *start,
                                     char *stop,
                                     char **extra_space,
                                     int *extra_len,
                                     bool loader) {
  _nx_debug_printf("patch syscalls in range %p-%p\n", start, stop);
  char *func = start;
  int nopcount = 0;
  bool has_syscall = false;
  for (char *ptr = start; ptr < stop; ptr++) {
    if ((*ptr == '\x0F' && ptr[1] == '\x05' /* SYSCALL */) || (lib->vdso && *ptr == '\xFF')
#ifdef __NX_INTERCEPT_RDTSC
        || (*ptr == '\x0F' && ptr[1] == '\x31' /* RDTSC */)
#endif
    ) {
      ptr++;
      has_syscall = true;
      nopcount = 0;
    } else if (*ptr == '\x90' /* NOP */) {
      nopcount++;
    } else if (!((long)ptr & 0xF)) {
      if (nopcount > 2) {
        // This is very likely the beginning of a new function. Functions are
        // aligned on 16 byte boundaries and the preceding function is padded
        // out with NOPs.
        //
        // For performance reasons, we quickly scan the entire text segment
        // for potential SYSCALLs, and then patch the code in increments of
        // individual functions.
        if (has_syscall) {
          has_syscall = false;
          // Quick scan of the function found a potential syscall, do thorough
          // scan
          _nx_debug_printf("patch syscalls in func after quick scan\n");
          patch_syscalls_in_func(lib, func, stop, extra_space, extra_len, loader);
        }
        func = ptr;
      }
      nopcount = 0;
    } else {
      nopcount = 0;
    }
  }
  _nx_debug_printf("has syscall? %u\n", has_syscall);
  if (has_syscall) {
    // Patch any remaining system calls that were in the last function before
    // the loop terminated.
    patch_syscalls_in_func(lib, func, stop, extra_space, extra_len, loader);
  }
  _nx_debug_printf("patched syscalls in range\n");
}
// Returns a pointer to a stripped version of pathname that corresponds
// to the library
const char *strip_pathname(const char *pathname)
{
  const char *real = pathname;

  for (const char *delim = " /"; *delim; ++delim) {
    const char *skip =
        strrchr(real, *delim);
    if (skip) {
      real = skip + 1;
    }
  }

  return real;
}

// Returns true if real library filename corresponds to bare library name
static bool lib_name_match(const char *bare, const char *pathname)
{
  const char *real = strip_pathname(pathname);

  const char *name;
  if ((name = strstr(real, bare)))
  {
    char ch = name[strlen(bare)];
    if (ch < 'A' || (ch > 'Z' && ch < 'a') || ch > 'z') {
        return true;
    }
  }

  return false;
}

// Returns a short version of the library (e.g. full path to libc.so.6 would
// result in string "libc"
static const char *lib_get_stripped_name(const char *pathname)
{
  const char *rtn_str = NULL;
  for (int i = 0; i < registered_icept_cnt; ++i)
  {
    if (lib_name_match(intercept_records[i].lib_name, pathname))
    {
      rtn_str = intercept_records[i].lib_name;
      goto rtn;
    }
  }

  for (const char **lib = known_syscall_libs; *lib != NULL; lib++)
  {
    if (lib_name_match(*lib, pathname))
    {
      rtn_str = *lib;
      goto rtn;
    }
  }

rtn:
  return rtn_str;
}

// Returns true if library defined by pathname has functions that we want to intercept
static bool lib_is_icepted(const char *pathname)
{
  for (int i = 0; i < registered_icept_cnt; ++i)
  {
    if (lib_name_match(intercept_records[i].lib_name, pathname))
      return true;
  }

  return false;
}

// TODO extract symbol (function) interception to a different function
static void patch_syscalls(struct library *lib, bool loader) {
  if (!lib->valid)
    return;

  _nx_debug_printf("rewriter: patching syscalls in -> (%s)\n", lib->pathname);

  int extra_len = 0;
  char *extra_space = NULL;

  /****************** TODO START extract symbol... ******************/
  if (lib_is_icepted(lib->pathname))
  {
    const char *short_libname = lib_get_stripped_name(lib->pathname);

    for (int i = 0; i < registered_icept_cnt; ++i)
    {
      if (!strcmp(short_libname, intercept_records[i].lib_name))
      {
        _nx_debug_printf("patching intercepts: %s\n", lib->pathname);
        struct section *scn = section_find(lib->section_hash, ".text");
        _nx_debug_printf(".text section %p\n", scn);
        if (!scn)
          return;

        const Elf_Shdr *shdr = &scn->shdr;
        char *addr = (char *)(shdr->sh_addr + lib->asr_offset);
        size_t size = round_up(shdr->sh_size, 0x1000);

        if (mprotect((void *)((long)addr & ~0xFFF),
                     size,
                     PROT_READ | PROT_WRITE | PROT_EXEC)) {
          _nx_debug_printf("mprotect failed\n");
          return;
        }
        _nx_debug_printf("mprotect done\n");

        struct symbol *sym = symbol_find(lib->symbol_hash, intercept_records[i].fn_name);
        if (sym != NULL && (void *)sym->sym.st_value != NULL) {
          _nx_debug_printf("patching at address %lx\n", (long)lib->asr_offset + sym->sym.st_value);
          api_detour_func(lib,
                                  lib->asr_offset + sym->sym.st_value,
                                  lib->asr_offset + sym->sym.st_value + sym->sym.st_size,
                                  intercept_records[i].callback,
                                  &extra_space,
                                  &extra_len);
        }
      }
    }
  }
  /****************** TODO END extract symbol... ******************/

  struct section *scn = section_find(lib->section_hash, ".text");
  // TODO if the section table has been stripped, we should look at executable segments instead
  if (!scn)
    return;

  _nx_debug_printf(".text section %p\n", scn);
  const Elf_Shdr *shdr = &scn->shdr;
  char *start = (char *)(shdr->sh_addr + lib->asr_offset);
  char *stop = start + shdr->sh_size;
  patch_syscalls_in_range(lib, start, stop, &extra_space, &extra_len, loader);

  _nx_debug_printf("mprotect extra space %p\n", extra_space);
  if (extra_space != NULL) {
    // Mark our scratch space as write-protected and executable.
    mprotect(extra_space, 0x1000, PROT_READ | PROT_EXEC);
  }
  _nx_debug_printf("mprotected\n");
}

static bool parse_symbols(struct library *lib) {
  if (!lib->valid)
    return false;

  Elf_Shdr str_shdr;
  ignore_result(library_get_original(
      lib,
      lib->ehdr.e_shoff + lib->ehdr.e_shstrndx * lib->ehdr.e_shentsize,
      &str_shdr));

  // Find symbol table
  struct section *scn = section_find(lib->section_hash, ".dynsym");
  const Elf_Shdr *symtab = scn ? &scn->shdr : NULL;
  Elf_Shdr strtab = {0};
  if (symtab) {
    if (symtab->sh_link >= lib->ehdr.e_shnum ||
        !library_get_original(
            lib,
            lib->ehdr.e_shoff + symtab->sh_link * lib->ehdr.e_shentsize,
            &strtab)) {
      _nx_debug_printf("WARN: cannot find valid symbol table\n");
      goto error;
    }

    // Parse symbol table and add its entries
    for (Elf_Addr addr = 0; addr < symtab->sh_size; addr += sizeof(Elf_Sym)) {
      Elf_Sym sym;
      if (!library_get_original(lib, symtab->sh_offset + addr, &sym) ||
          (sym.st_shndx >= lib->ehdr.e_shnum && sym.st_shndx < SHN_LORESERVE)) {
        _nx_debug_printf("WARN: encountered invalid symbol\n");
        goto error;
      }
      const char *name =
          library_copy_original(lib, strtab.sh_offset + sym.st_name);
      _nx_debug_printf("parse_symbols: name copied\n");
      if (!strlen(name))
        continue;

      struct symbol *ls = malloc(sizeof(*ls));
      symbol_init(ls, name, sym);
      symbol_add(lib->symbol_hash, ls);
      _nx_debug_printf("parse_symbols: symbol %s (%p)\n", name, (void *)addr);
    }
  }

  return true;

error:
  _nx_debug_printf("shit!\n");
  lib->valid = false;
  return false;
}

bool parse_elf(struct library *lib, const char * prog_name) {
  lib->valid = true;

  // Verify ELF header
  Elf_Shdr str_shdr;
  if (!library_get_original(lib, 0, &lib->ehdr) ||
      lib->ehdr.e_ehsize < sizeof(Elf_Ehdr) ||
      lib->ehdr.e_phentsize < sizeof(Elf_Phdr) ||
      lib->ehdr.e_shentsize < sizeof(Elf_Shdr) ||
      !library_get_original(
          lib,
          lib->ehdr.e_shoff + lib->ehdr.e_shstrndx * lib->ehdr.e_shentsize,
          &str_shdr)) {
    _nx_debug_printf("parse_elf: header invalid\n");
    goto error;
  }

  // Parse section table and find all sections in this ELF file
  for (int i = 0; i < lib->ehdr.e_shnum; i++) {
    Elf_Shdr shdr;
    if (!library_get_original(
            lib, lib->ehdr.e_shoff + i * lib->ehdr.e_shentsize, &shdr))
      continue;

    struct section *scn = malloc(sizeof(*scn));
    section_init(scn,
                 library_copy_original(lib, str_shdr.sh_offset + shdr.sh_name),
                 i,
                 shdr);
    section_add(lib->section_hash, scn);
    _nx_debug_printf("[%u] section %s\n", i, scn->name);
  }

  // Compute the offset of entries in the .text segment
  struct section *scn = section_find(lib->section_hash, ".text");
  const Elf_Shdr *text = scn ? &scn->shdr : NULL;
  if (!text) {
    _nx_debug_printf("parse_elf: failed to find .text\n");
    goto error;
  }

  // Now that we know where the .text segment is located, we can compute the
  // asr_offset_
  struct region *rgn = rb_lower_bound_region(lib, text->sh_offset);
  if (!rgn) {
    _nx_debug_printf("parse_elf: failed to find .text region\n");
    goto error;
  }

  _nx_debug_printf("region %lu\n", rgn->offset);
  lib->asr_offset =
      (char *)rgn->start - (text->sh_addr - (text->sh_offset - rgn->offset));
  _nx_debug_printf("asr offset %p\n", lib->asr_offset);

  if (prog_name && !strcmp(lib->pathname, prog_name))
    return parse_symbols(lib);

  const char * libnames[] = { "[vdso]", "libc" , "libpthread" , NULL };
  if (which_lib_name_interesting(libnames, lib->pathname) >= 0)
    return parse_symbols(lib);
  else
    return true;

error:
  _nx_debug_printf("rewriter: failed to parse\n");
  lib->valid = false;
  return false;
}

int which_lib_name_interesting(const char * interesting_libs[], const char * pathname) {
  const char *mapping = pathname;
  for (const char *delim = " /"; *delim; ++delim) {
    // Find the actual base name of the mapped library by skipping past
    // any SPC and forward-slashes. We don't want to accidentally find
    // matches, because the directory name included part of our well-known
    // lib names.
    //
    // Typically, prior to pruning, entries would look something like
    // this: 08:01 2289011 /lib/libc-2.7.so
    const char *skip = strrchr(mapping, *delim);  // TODO: do this at maps_read?
    if (skip) {
      mapping = skip + 1;
    }
  }

  for (const char **lib = interesting_libs; *lib; lib++) {
    const char *name = strstr(mapping, *lib);
    if (name != NULL) {
      char ch = name[strlen(*lib)];
      if (ch < 'A' || (ch > 'Z' && ch < 'a') || ch > 'z') {
          return lib - interesting_libs;
      }
    }
  }

  return -1;
}

bool is_lib_name_interesting (const char * interesting_lib, const char * pathname) {
  const char * libnames[] = { interesting_lib, NULL };
  return which_lib_name_interesting(libnames, pathname) == 0;
}

void memorymaps_rewrite_lib(const char* libname) {
  struct maps* maps = maps_read(libname);
  if (maps == NULL)
    _nx_fatal_printf("memrewrite: couldn't find library %s, when we should had\n", libname);

  struct library* l;
  int guard = 0; // Test that we always find exactly 1 library
  for_each_library(l, maps) {
    if (parse_elf(l, libname)) {
      _nx_debug_printf("memrewrite: patching syscalls in library %s\n", l->pathname);
      library_make_writable(l, true);
      patch_syscalls(l, false);
      library_make_writable(l, false);
    }
    guard++;
  }
  assert(guard == 1);

  maps_release(maps);
  _nx_debug_printf("memrewrite: done processing libraries\n");
}

void memorymaps_rewrite_all(const char * libs[], const char * bin, bool loader) {
  // We find all libraries that have system calls and redirect the system
  // calls to the sandbox. If we miss any system calls, the application will
  // be terminated by the kernel's seccomp code. So, from a security point of
  // view, if this code fails to identify system calls, we are still behaving
  // correctly.
  struct maps* maps = maps_read(NULL);

  // Intercept system calls in the VDSO segment (if any). This has to happen
  // before intercepting system calls in any of the other libraries, as the
  // main kernel entry point might be inside of the VDSO and we need to
  // determine its address before we can compare it to jumps from inside
  // other libraries.

  if (maps->lib_vdso != NULL && parse_elf(maps->lib_vdso, bin)) {
    _nx_debug_printf("memrewrite: patching vdso\n");
    library_make_writable(maps->lib_vdso, true);
    patch_vdso(maps->lib_vdso);
    library_make_writable(maps->lib_vdso, false);
    _nx_debug_printf("memrewrite: vsdo done\n");
  }

  // Intercept system calls in libraries that are known to have them.
  struct library *l;
  for_each_library(l, maps) {
    _nx_debug_printf("memrewrite: processing library %s\n", l->pathname);
    bool is_bin = false;
    if ((which_lib_name_interesting(libs, l->pathname) >= 0
            || (bin && (is_bin = !strcmp(l->pathname, bin)))) // FIXME here bin should be the full path
        && parse_elf(l, bin)) {
      _nx_debug_printf("memrewrite: patching syscalls in library %s\n", l->pathname);
      library_make_writable(l, true);
      patch_syscalls(l, is_bin ? false : loader);
      library_make_writable(l, false);
    }
  }

  maps_release(maps);
  _nx_debug_printf("memrewrite: done processing libraries\n");
}
