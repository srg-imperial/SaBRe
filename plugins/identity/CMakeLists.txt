include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/plugins)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Werror -Wno-error=unused-parameter")

add_library(identity SHARED ${CMAKE_SOURCE_DIR}/libsrc/real_syscall.s
                            ${CMAKE_SOURCE_DIR}/libsrc/clone_syscall.s
                            identity.c)

option(RDTSC          "Intercept instruction RDTSC as a system call" ON)

if (RDTSC)
  add_definitions(-D__NX_INTERCEPT_RDTSC)
endif(RDTSC)
