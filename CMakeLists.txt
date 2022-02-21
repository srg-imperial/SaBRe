# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required (VERSION 2.8)

set(CMAKE_USER_MAKE_RULES_OVERRIDE_C "${CMAKE_CURRENT_SOURCE_DIR}/cmake/c_flags_override.cmake")

project (SaBRe C ASM CXX)

find_program(GCC_PATH gcc)

set(SABRE_COMPONENT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/includes")
set(SABRE_COMPONENT_C_DEFINES "")
set(SABRE_COMPONENT_C_FLAGS "-std=gnu99" "-Wall" "-Wextra" "-Werror" "-fPIE" "-fstack-protector" "-fno-common")
set(SABRE_EXE_LINK_FLAGS "-pie" "-rdynamic")
set(SABRE_PLUGIN_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/includes/plugins")
set(SABRE_PLUGIN_C_DEFINES "")
set(SABRE_PLUGIN_C_FLAGS "-std=gnu99")

option(DEBUG_INTERNAL "Print debug messages" OFF)
if (DEBUG_INTERNAL)
  list(APPEND SABRE_COMPONENT_C_DEFINES "-DSBR_DEBUG")
  list(APPEND SABRE_PLUGIN_C_DEFINES "-DSBR_DEBUG")
endif ()

if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
  option(RDTSC "Intercept instruction RDTSC as a system call" ON)
  if (RDTSC)
    list(APPEND SABRE_COMPONENT_C_DEFINES "-D__NX_INTERCEPT_RDTSC")
    list(APPEND SABRE_PLUGIN_C_DEFINES "-D__NX_INTERCEPT_RDTSC")
  endif()
endif()

include("${CMAKE_SOURCE_DIR}/cmake/sabre_add_component.cmake")

# Sources
add_subdirectory("arch/${CMAKE_SYSTEM_PROCESSOR}" arch)
add_subdirectory("loader")
file(GLOB subdirs CONFIGURE_DEPENDS "plugins/*")
foreach(subdir ${subdirs})
  add_subdirectory(${subdir})
endforeach()
add_subdirectory("tests")
