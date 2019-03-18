if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "riscv64")

include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/arch)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=gnu99 -Wall -Wextra -Werror -fPIE -fstack-protector")

set(SRCS
  handle_syscall.s
  handle_syscall_loader.s
  handle_vdso.s
  real_syscall.s
  rewriter.c
  riscv_decoder.c
  riscv_utils.c
  syscall_stackframe.c
)

if (DEBUG)
  add_definitions(-DSBR_DEBUG)
endif(DEBUG)

# Build library
add_library(riscv64 STATIC ${SRCS})
target_link_libraries(riscv64 loader)

endif()