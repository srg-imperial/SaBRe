include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/includes/loader)

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

add_subdirectory(tools)
