include_directories(${CMAKE_SOURCE_DIR}/includes)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=gnu99 -Wall -Wextra -Werror -fPIE -fstack-protector")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -rdynamic")

set(SRCS
  elf_loading.c
  handle_syscall.S
  handle_syscall_loader.s
  handle_vdso.s
  ld_sc_handler.c
  rewriter.c
  loader.c
  maps.c
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
add_library(loader ${SRCS})
target_include_directories(loader PUBLIC ./includes)
target_link_libraries(loader dl)

# Build loader
add_executable(sabre main.s)
set_target_properties(sabre PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(sabre loader libsrc)

# Build tools
add_executable(process-vdso tools/process-vdso.c)
add_executable(dump-vdso    tools/dump-vdso.c)

target_compile_options(dump-vdso PRIVATE "-Wno-unused-parameter")
target_compile_options(process-vdso PRIVATE "-Wno-unused-parameter")

target_include_directories(process-vdso PRIVATE ./includes)
target_include_directories(dump-vdso PRIVATE ./includes)

target_link_libraries(process-vdso loader)
target_link_libraries(dump-vdso    loader)
