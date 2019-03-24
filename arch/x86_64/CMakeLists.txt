include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/arch)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")

set(SRCS
  clone_syscall.s
  handle_syscall.S
  handle_syscall_loader.s
  handle_vdso.s
  real_syscall.s
  rewriter.c
  syscall_stackframe.c
  x86_decoder.c
)

if (RDTSC)
  list(APPEND SRCS handle_rdtsc.s)
endif(RDTSC)

add_library(x86_64 STATIC ${SRCS})
target_compile_options(x86_64 PRIVATE ${SABRE_LOADER_C_COMPILE_OPTIONS})
target_link_libraries(x86_64 loader)

sabre_add_main_executable(main.s)
target_link_libraries(sabre libsrc)
