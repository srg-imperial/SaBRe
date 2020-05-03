include(ExternalProject)

set(MIMALLOC_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/mimalloc/install)

ExternalProject_Add(
  mimalloc
  PREFIX mimalloc
  GIT_REPOSITORY https://github.com/microsoft/mimalloc.git
  GIT_TAG 81bd1b70b086d872bda515f99cfcf0d78f8ac86c # dev branch v1.6.3 + #240
  INSTALL_DIR ${MIMALLOC_INSTALL_DIR}
  # We need to patch mimalloc's default mmap ranges as they interfere with
  # sanitizers
  # https://github.com/llvm/llvm-project/blob/master/compiler-rt/lib/tsan/rtl/tsan_platform.h#L67-L72
  PATCH_COMMAND
    patch -p1 <
    ${CMAKE_CURRENT_SOURCE_DIR}/mimalloc-sanitizer-compatibility.patch
  CMAKE_ARGS
    "-DCMAKE_INSTALL_PREFIX=${MIMALLOC_INSTALL_DIR};-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE};-DMI_LOCAL_DYNAMIC_TLS=ON;"
)

set(IS_DEBUG "")
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LC)
if(CMAKE_BUILD_TYPE_LC STREQUAL "debug")
  set(IS_DEBUG "-debug")
endif()

set(MIMALLOC_STATIC_LIB
    ${MIMALLOC_INSTALL_DIR}/lib/mimalloc-1.6/libmimalloc${IS_DEBUG}.a pthread)
