.file "main.s"

.data
null_entry:
  .string "FATAL: entry point is null\n"
null_new_stack:
  .string "FATAL: new stack top is null\n"

.text
.global main
.type main, @function

main:
  # Function prologue
  addi sp, sp, -8
  sd ra, 0(sp) #store return address

  addi sp, sp, -8
  sd s0, 0(sp) #save frame pointer
  addi s0, sp, 0 


   # Push two NULL pointers onto stack and pass them to load
  addi sp, sp, -8
  sd x0, 0(sp)
  addi a2, sp, 0 # pass the third argument of main to load
  addi sp, sp, -8
  sd x0, 0(sp)
  addi a3, sp, 0 # pass the fourth arugment of main to load


  # call the main loading function
  # call *load@GOTPCREL(pc)
  call load

  # todo sanity check

  # Evyerthing seems fine, nuke the stack

  addi t0, a0, 0 # new stack
  ld t1, -8(t0) # new return address
  
  #addi sp, s0, -16
  xor s0, s0, s0

  # Nothing at_exit()
  xor a2, a2, a2
 
  #addi a0, t3, 0
  #ld a0, 0(a0)
  #call p
  # Call the entrypoint of the loader/static 
  addi a0, x0, 0
  addi sp, t0, 0
  jr t1

  #call p

  # if didn't end, force end
  addi x17, x0, 93
  ecall

error_entrypoint:


error_new_stack:


.size main, .-main
.section .note,"",@progbits
