include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/loader)

set(CMAKE_C_FLAGS_DEBUG "-ggdb3")
set(SABRE_LOADER_C_COMPILE_OPTIONS ${SABRE_C_COMPILE_OPTIONS} "-fPIE" "-fstack-protector")

add_subdirectory(${CMAKE_SOURCE_DIR}/arch/${CMAKE_SYSTEM_PROCESSOR} arch)

# Build library
add_library(loader
  elf_loading.c
  ld_sc_handler.c
  loader.c
  maps.c
  rewriter.c
)

target_link_libraries(loader ${CMAKE_DL_LIBS} ${CMAKE_SYSTEM_PROCESSOR})

# Build tools
add_executable(process-vdso tools/process-vdso.c)
add_executable(dump-vdso    tools/dump-vdso.c)

target_compile_options(dump-vdso PRIVATE "-Wno-unused-parameter")
target_compile_options(process-vdso PRIVATE "-Wno-unused-parameter")

target_include_directories(process-vdso PRIVATE ${CMAKE_SOURCE_DIR}/includes/arch)
target_include_directories(dump-vdso PRIVATE ./includes)

target_link_libraries(process-vdso loader)
target_link_libraries(dump-vdso    loader)
