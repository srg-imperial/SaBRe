include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/loader)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")
set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-std=gnu99 -Wall -Wextra -Werror -fPIE -fstack-protector")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -rdynamic")

set(SRCS
  elf_loading.c
  ld_sc_handler.c
  loader.c
  maps.c
  rewriter.c
)

option(RDTSC          "Intercept instruction RDTSC as a system call" ON)

if (DEBUG)
  add_definitions(-DSBR_DEBUG)
endif(DEBUG)

if (RDTSC)
  add_definitions(-D__NX_INTERCEPT_RDTSC)
endif(RDTSC)

# Build library
add_library(loader ${SRCS})
target_link_libraries(loader dl x86_64)

# Build loader
add_executable(sabre ${CMAKE_SOURCE_DIR}/arch/x86_64/main.s)
set_target_properties(sabre PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(sabre loader libsrc)

# Build tools
add_executable(process-vdso tools/process-vdso.c)
add_executable(dump-vdso    tools/dump-vdso.c)

target_compile_options(dump-vdso PRIVATE "-Wno-unused-parameter")
target_compile_options(process-vdso PRIVATE "-Wno-unused-parameter")

target_include_directories(process-vdso PRIVATE ${CMAKE_SOURCE_DIR}/includes/arch)
target_include_directories(dump-vdso PRIVATE ./includes)

target_link_libraries(process-vdso loader)
target_link_libraries(dump-vdso    loader)
