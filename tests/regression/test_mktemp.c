/*
 * REQUIRES: rdtsc
 * RUN: %{cc} %s -o %t1
 * RUN: %{vx} %t1 &> %t1.actual
 * RUN: echo "Success" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main() {
  char template[] = "tmpXXXXXX";

  mktemp(template);

  assert(strlen(template) > 0);

  struct stat buf;
  assert(stat(template, &buf) == -1);

  printf("Success\n");
  return 0;
}
