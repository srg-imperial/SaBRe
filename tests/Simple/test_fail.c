/*
 * RUN: %{cc} %s -o %t1
 * RUN: ! %{vx} %t1 %t1 &> %t1.actual
 * RUN: grep "Assertion" %t1.actual
 */

// The problem with this test is that the following program if run under
// normal circumstances is killed by a signal and exits with code: 134.
// Unfortunately, in this case, Varan exits with 0.

#include <assert.h>

int main(int argc, char **argv) {
  assert(0);
  return 0;
}
