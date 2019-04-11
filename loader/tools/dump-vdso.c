/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <arch/rewriter_tools.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <elf.h>

#include "compiler.h"
#include "config.h"
#include "kernel.h"
#include "loader/maps.h"


int main(int argc, char **argv, char **envp) {
  int out_fd = open(argv[1], O_WRONLY | O_CREAT, 00600);
  struct maps *maps = maps_read(NULL);

  struct library *l;
  struct region *reg;
  struct region *n;

  for_each_library(l, maps) {
    if (l->vdso) {
      rbtree_postorder_for_each_entry_safe(reg, n, &l->rb_region, rb_region) {
        long written = 0;
        long size = reg->end - reg->start;

        while (written != size)
          written += write(out_fd, reg->start + written, size - written);

        break;
      }
    }
  }

  close(out_fd);

  return 0;
}
