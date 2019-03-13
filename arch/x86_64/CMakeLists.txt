if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")

include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/arch)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=gnu99 -Wall -Wextra -Werror -fPIE -fstack-protector")

set(SRCS
  handle_syscall.S
  handle_syscall_loader.s
  handle_vdso.s
  rewriter.c
  x86_decoder.c
)

option(RDTSC          "Intercept instruction RDTSC as a system call" ON)

if (DEBUG)
  add_definitions(-DSBR_DEBUG)
endif(DEBUG)

if (RDTSC)
  add_definitions(-D__NX_INTERCEPT_RDTSC)
  set(SRCS ${SRCS} handle_rdtsc.s)
endif(RDTSC)

# Build library
add_library(x86_64 STATIC ${SRCS})
target_link_libraries(x86_64 loader)

endif()