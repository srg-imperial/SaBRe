/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../loader/rewriter.c"
#include "../maps.c"
#include "compiler.h"
#include "kernel.h"

// TODO(andronat): We should use this code as a unit test

extern struct region *rb_insert_region(struct library *library,
                                       ElfW(Addr) offset, struct rb_node *node);

int main(int argc, char **argv, char **envp) {
  //  Take vdso elf file as first argument
  char *vdso = argv[1];

  // Open vdso
  int vdso_fd = open(vdso, O_RDONLY, 00600);
  // Get file size
  struct stat vdso_stat;
  fstat(vdso_fd, &vdso_stat);

  //  mmap it
  void *start_addr = (caddr_t)mmap(
      NULL, vdso_stat.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, vdso_fd, 0);

  //  Close vdso
  close(vdso_fd);

  //  Set up library with vdso
  void *start = start_addr;
  void *end = start_addr + vdso_stat.st_size;
  char *pathname = vdso;

  /* allocate a new region structure */
  struct region *reg = (struct region *)malloc(sizeof(struct region));
  assert(reg != NULL);

  reg->start = (void *)start;
  reg->end = (void *)end;
  reg->size = (size_t)(end - start);

  // Setup protection permissions
  int perms = PROT_NONE;
  perms |= PROT_READ;
  perms |= PROT_WRITE;
  perms |= PROT_EXEC;
  perms |= MAP_PRIVATE;
  reg->perms = perms;
  reg->type = REGION_VDSO;

  struct library lib = {0};
  struct maps maps = {0};

  // SaBRe needs this fd to find scratch space to mmap
  maps.fd = open("/proc/self/maps", O_RDONLY, 0);
  library_init(&lib, pathname, &maps);

  rb_insert_region(&lib, 0L, &reg->rb_region);

  lib.vdso = true;
  parse_elf(&lib, NULL);

  //  Call library_patch_syscalls
  patch_syscalls(&lib, false);

  //  write the result to the second argument
  int result_fd = open(argv[2], O_WRONLY | O_CREAT, 00600);

  long size = vdso_stat.st_size;
  long written = 0;

  while (written != size)
    written += write(result_fd, start + written, size - written);

  close(result_fd);
  return 0;
}
