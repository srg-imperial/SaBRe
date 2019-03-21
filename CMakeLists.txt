cmake_minimum_required (VERSION 2.8)
project (SaBRe C ASM)

find_program(GCC_PATH gcc)

option(DEBUG "Print debug messages" OFF)
if (DEBUG)
  add_definitions(-DSBR_DEBUG)
endif(DEBUG)

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  option(RDTSC "Intercept instruction RDTSC as a system call" ON)
  if (RDTSC)
    add_definitions(-D__NX_INTERCEPT_RDTSC)
  endif()
endif()

# Sources
add_subdirectory("libsrc")
add_subdirectory("loader")
file(GLOB subdirs CONFIGURE_DEPENDS "plugins/*")
foreach(subdir ${subdirs})
  add_subdirectory(${subdir})
endforeach()
file(GLOB subdirs CONFIGURE_DEPENDS "arch/*")
foreach(subdir ${subdirs})
  add_subdirectory(${subdir})
endforeach()
