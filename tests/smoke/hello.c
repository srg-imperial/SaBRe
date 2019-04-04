/*
 * RUN: %{gcc} %s -o %t1
 * RUN: %{sbr} %t1 &> /dev/null
 * RUN: %{sbrtrace} %t1 &> /dev/null
 * RUN: %{fault-injector} %t1
 */
#include <stdio.h>

int main(int argc, char *argv[]) {
  printf("Hello World!\n");
  return 0;
}
