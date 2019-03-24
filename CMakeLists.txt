cmake_minimum_required (VERSION 2.8)

set(CMAKE_USER_MAKE_RULES_OVERRIDE_C "${CMAKE_CURRENT_SOURCE_DIR}/cmake/c_flags_override.cmake")

project (SaBRe C ASM)

find_program(GCC_PATH gcc)

set(SABRE_C_COMPILE_OPTIONS "-std=gnu99" "-Wall" "-Wextra" "-Werror")
set(SABRE_PLUGIN_C_COMPILE_OPTIONS "-std=gnu99")

option(DEBUG_INTERNAL "Print debug messages" OFF)
if (DEBUG_INTERNAL)
  add_definitions(-DSBR_DEBUG)
endif ()

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  option(RDTSC "Intercept instruction RDTSC as a system call" ON)
  if (RDTSC)
    add_definitions(-D__NX_INTERCEPT_RDTSC)
  endif()
endif()

include("${CMAKE_SOURCE_DIR}/cmake/sabre_add_component.cmake")

# Sources
if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  add_subdirectory("libsrc")
endif ()
add_subdirectory("loader")
file(GLOB subdirs CONFIGURE_DEPENDS "plugins/*")
foreach(subdir ${subdirs})
  add_subdirectory(${subdir})
endforeach()
add_subdirectory("tests")
