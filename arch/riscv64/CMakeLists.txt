include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/arch)

sabre_add_component(riscv64
  clone_syscall.c
  handle_syscall.s
  handle_syscall_loader.s
  handle_vdso.s
  real_syscall.s
  rewriter.c
  riscv_decoder.c
  riscv_utils.c
  syscall_stackframe.c
)

target_link_libraries(riscv64 loader)

sabre_add_main_executable(main.s)
