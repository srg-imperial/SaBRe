# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# The patchelf utility comes from <https://github.com/NixOS/patchelf>. It was
# last updated from commit
#
#   a99261672293e50e7bc2de414a50a03ec62d4085
#
# and has been modified to work with Sabre. See the sections in patchelf.cc
# where `#ifdef SABRE` is used to see what has been modified from the original.
# All modifications should be contained by that preprocessor definition.

add_library(patchelf STATIC patchelf.cc)
set_property(TARGET patchelf PROPERTY POSITION_INDEPENDENT_CODE ON)
# Define 'SABRE' to make it easy to distinguish our changes to patchelf.
target_compile_definitions(patchelf PRIVATE "-DSABRE")

# Uncomment this to also build the patchelf executable utility which may be
# helpful for debugging purposes.
#add_executable(patchelf2 patchelf.cc)
