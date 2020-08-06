# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_COMPONENT_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/includes/loader)

set(PROTECTOR ${CMAKE_CURRENT_SOURCE_DIR}/recursion_protector.c PARENT_SCOPE)

# Build library
sabre_add_component(loader
  elf_loading.c
  ld_sc_handler.c
  loader.c
  maps.c
  premain.c
  ${PROTECTOR}
  rewriter.c
)

add_library(patchelf STATIC patchelf.cpp)

target_link_libraries(loader ${CMAKE_DL_LIBS} realsyscall backend patchelf elf)

add_subdirectory(tools)
