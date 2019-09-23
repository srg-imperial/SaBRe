# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_COMPONENT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/includes/arch")

set(SABRE_COMPONENT_C_FLAGS "${SABRE_COMPONENT_C_FLAGS}" "-Wno-unused-parameter")

set(SRCS
  handle_syscall.S
  handle_syscall_loader.s
  handle_vdso.s
  rewriter.c
  syscall_stackframe.c
  x86_decoder.c
)

if (RDTSC)
  list(APPEND SRCS handle_rdtsc.s)
endif(RDTSC)

sabre_add_component(backend ${SRCS})

sabre_add_component(realsyscall
  clone_syscall.s
  real_syscall.s)

target_link_libraries(backend loader)

add_subdirectory("${CMAKE_SOURCE_DIR}/libsrc" "${CMAKE_BINARY_DIR}/libsrc")

sabre_add_executable(sabre main.s)
set_target_properties(sabre PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
target_link_libraries(sabre libsrc)
