/*  Copyright © 2019 Software Reliability Group, Imperial College London
 *
 *  This file is part of SaBRe.
 *
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <stdbool.h>

// Sanitizers intercept various function calls, look here:
// https://github.com/llvm/llvm-project/blob/b3ca4f34311b87345cf87bfdd0343045eed22f5c/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc#L5185
// In various TLS models _Thread_local variables calls __tls_get_addr to resolve
// its value. Unfortunately these modes crash LLVM sanitizers in the above
// function. The LLVM sanitizers themselves actually use initial-exec to avoid
// this problem. initial-exec doesn't go through __tls_get_addr but rather uses
// the %fs register directly.
// In the current setup, we need "initial-exec" as runtime_syscall_router will
// be called during pthread initialization which will happen before the
// sanitizers initialization phase.
// TODO(andronat): Will the following create any issues with other libraries?
// e.g. overlapping offsets and thus writting/reading from wrong variables?
static _Thread_local
    __attribute__((tls_model("initial-exec"))) bool from_plugin = false;

bool calling_from_plugin() { return from_plugin; }
void enter_plugin() { from_plugin = true; }
void exit_plugin() { from_plugin = false; }
