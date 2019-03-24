include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/arch)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=gnu99 -Wall -Wextra -Werror -fPIE -fstack-protector")

add_library(riscv64 STATIC ${SRCS}
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
target_compile_options(riscv64 ${SABRE_LOADER_C_COMPILE_OPTIONS})
target_link_libraries(riscv64 loader)

sabre_add_main_executable(main.s)
