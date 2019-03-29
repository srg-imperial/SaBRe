/* REQUIRES: clang,tsan
 * RUN: ulimit -s 32768
 * RUN: %{gcc} -fsanitize=thread %s -o %t1
 * RUN: %{clang} -fsanitize=thread %s -o %t2
 * RUN: %{sbr} %t1 &> %t1.actual
 * RUN: %{sbr} %t2 &> %t2.actual
 * RUN: echo "Hello, world!" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 * RUN: diff %t2.actual %t1.expected
 */

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  printf("Hello, world!\n");
  return 0;
}
