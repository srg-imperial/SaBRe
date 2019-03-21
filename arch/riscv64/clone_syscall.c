#include "macros.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"

long clone_syscall (unsigned long flags,
            void *child_stack,
            int *ptid, int *ctid,
            unsigned long newtls,
            void** args
            ) {
  _nx_fatal_printf("clone_syscall() is not implemented on RISC-V arch\n");
}
