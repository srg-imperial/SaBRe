# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

list(APPEND SABRE_COMPONENT_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/includes/loader)
list(APPEND SABRE_COMPONENT_C_FLAGS "-fPIC" "-fstack-protector")

add_subdirectory(${CMAKE_SOURCE_DIR}/arch/${CMAKE_SYSTEM_PROCESSOR} arch)

# Build library
sabre_add_component(loader
  elf_loading.c
  ld_sc_handler.c
  loader.c
  maps.c
  rewriter.c
)

target_link_libraries(loader ${CMAKE_DL_LIBS} ${CMAKE_SYSTEM_PROCESSOR})

add_subdirectory(tools)
