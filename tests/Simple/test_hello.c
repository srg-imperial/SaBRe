/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %t1 &> %t1.actual
 * RUN: echo "Hello, world!" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  printf("Hello, world!\n");
  return 0;
}
