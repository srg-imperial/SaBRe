# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_COMPONENT_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/includes/arch")

set(SRCS
  clone_syscall.s
  handle_syscall.S
  handle_syscall_loader.s
  handle_vdso.s
  real_syscall.s
  rewriter.c
  syscall_stackframe.c
  x86_decoder.c
)

if (RDTSC)
  list(APPEND SRCS handle_rdtsc.s)
endif(RDTSC)

sabre_add_component(x86_64 ${SRCS})
target_link_libraries(x86_64 loader)

add_subdirectory("${CMAKE_SOURCE_DIR}/libsrc" "${CMAKE_BINARY_DIR}/libsrc")

sabre_add_main_executable(main.s)
target_link_libraries(sabre libsrc)
