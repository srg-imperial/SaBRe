.file "dl_init_hook.s"
.text
.globl dl_init_hook
.type dl_init_hook, @function

# libc_start_main_hook is run right before libc_start_main
# It allows to alter syscall tables between loadtime and runtime

dl_init_hook:
  # Save arguments
  pushq %rdi
  pushq %rsi
  pushq %rbx
  pushq %rdx
  pushq %rcx
  pushq %r8
  pushq %r9
  pushq %r10
  pushq %r11
  pushq %r12
  pushq %r13
  pushq %r14
  pushq %r15
  pushq %rax

  # Align the stack on a 16-byte boundary before the call
  pushq %rbp
  mov %rsp, %rbp
  and $0xfffffffffffffff0, %rsp

  # Call our function
  call *sbr_dl_init@GOTPCREL(%rip)

  # Restore the stack
  mov %rbp, %rsp
  popq %rbp

  # Restore arguments
  popq %rax
  popq %r15
  popq %r14
  popq %r13
  popq %r12
  popq %r11
  popq %r10
  popq %r9
  popq %r8
  popq %rcx
  popq %rdx
  popq %rbx
  popq %rsi
  popq %rdi

  # Back to the original function
  mov real_dl_init@GOTPCREL(%rip), %r11
  jmp *0(%r11)

.size dl_init_hook, .-dl_init_hook
.section .note.GNU-stack,"",@progbits
