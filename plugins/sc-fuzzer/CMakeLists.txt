include_directories(${CMAKE_SOURCE_DIR}/includes)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Werror -Wno-error=unused-parameter")

add_library(sc-fuzzer SHARED ${CMAKE_SOURCE_DIR}/libsrc/real_syscall.s sc-fuzzer.c)

