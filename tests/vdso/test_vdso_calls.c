/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{sbr} %t1 &> %t1.actual
 * RUN: echo "Success" > %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <stdlib.h>

#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <assert.h>

/* Utility functions */

/* Tests */

static void test_clock_gettime() {
  struct timespec t;
  assert(syscall(SYS_clock_gettime, CLOCK_REALTIME, &t, NULL) == 0);
}

static void test_gettimeofday() {
  struct timeval t;
  assert(syscall(SYS_gettimeofday, &t, NULL, NULL) == 0);
}

static void test_time() {
  assert(syscall(SYS_time, NULL, NULL, NULL) != -1);
}

static void test_getcpu() {
  int cpu, node;
  assert(syscall(SYS_getcpu, &cpu, &node, NULL) == 0);
}

int main(int argc, char **argv) {
  /* Set-up */

  /* Test */
  test_time();
  test_getcpu();
  test_gettimeofday();
  test_clock_gettime();

  /* Tear-down */

  printf("Success\n");

  return 0;
}
