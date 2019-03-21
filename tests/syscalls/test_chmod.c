// RUN: %{cc} %s -o %t1
// RUN: rm %t3 || true
// RUN: touch %t3
// RUN: %{vx} %t1 %t3 2>&1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>

int main(int argc, char ** argv) {

  if (chmod(argv[1], 00755) < 0)
    return 1;

  return 0;
}
