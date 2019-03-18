  .file "clone_syscall.s"
  .text
  .globl clone_syscall
  .type clone_syscall, @function

# long clone (unsigned long flags,
#             void *child_stack,	# %rsi
#             int *ptid, int *ctid,
#             unsigned long newtls,
#             void* ret_addr			# %r9
#             );
clone_syscall:
  pushq %rbp
  movq %rsp, %rbp

  # Set up child arguments, including return address
  movq %r9, -8(%rsi)

  # Adjust the arguments
  movq $56, %rax
  movq %rcx, %r10
  syscall            # syscall

  # Both child and parent return here
  testq  %rax, %rax
  jnz    1f

  # Child
  movq -8(%rsp), %r11
  subq $128, %rsp
  jmp *%r11

1:
  # Parent
  popq %rbp
  ret

  .size clone_syscall, .-clone_syscall
  .section .note.GNU-stack,"",@progbits
