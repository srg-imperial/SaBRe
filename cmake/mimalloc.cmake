include(ExternalProject)

set(MIMALLOC_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/mimalloc/install)

ExternalProject_Add(
  mimalloc
  PREFIX mimalloc
  GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
  GIT_TAG v1.6.3
  INSTALL_DIR ${MIMALLOC_INSTALL_DIR}
  # We need to patch mimalloc's default mmap ranges as they interfere with
  # sanitizers
  # https://github.com/llvm/llvm-project/blob/master/compiler-rt/lib/tsan/rtl/tsan_platform.h#L67-L72
  PATCH_COMMAND
    patch -p1 <
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/mimalloc-sanitizer-compatibility.patch
  UPDATE_COMMAND ""
  CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${MIMALLOC_INSTALL_DIR};-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE};-DMI_LOCAL_DYNAMIC_TLS=ON;"
)

set(IS_DEBUG "")
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LC)
if(CMAKE_BUILD_TYPE_LC STREQUAL "debug")
  set(IS_DEBUG "-debug")
endif()

find_package(Threads REQUIRED)
add_library(mimalloc-static STATIC IMPORTED GLOBAL)
add_dependencies(mimalloc-static mimalloc)
set_target_properties(
  mimalloc-static
  PROPERTIES IMPORTED_LOCATION
             ${MIMALLOC_INSTALL_DIR}/lib/mimalloc-1.6/libmimalloc${IS_DEBUG}.a
             INTERFACE_LINK_LIBRARIES ${CMAKE_THREAD_LIBS_INIT})
