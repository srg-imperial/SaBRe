add_library(libsrc STATIC malloc/malloc.c malloc/mlock.c)
target_include_directories(libsrc PRIVATE ${CMAKE_SOURCE_DIR}/includes)
target_compile_options(libsrc PRIVATE ${SABRE_C_COMPILE_OPTIONS} "-fPIC")
