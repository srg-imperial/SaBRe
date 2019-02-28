#ifndef REAL_SYSCALL_H
#define REAL_SYSCALL_H
long real_syscall(long sc_no,
                  long arg1,
                  long arg2,
                  long arg3,
                  long arg4,
                  long arg5,
                  long arg6);

long clone_syscall (unsigned long flags,
            void *child_stack,
            int *ptid, int *ctid,
            unsigned long newtls,
            void** args
            );

#endif /* !REAL_SYSCALL_H */
