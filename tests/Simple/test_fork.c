/*
 * RUN: %{cc} %s -o %t1
 * RUN: echo "abc" >  %t1.expected
 * RUN: echo "def" >> %t1.expected
 * RUN: timeout 5 %{vx} %t1 &> %t1.actual
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>

int main(int argc, char **argv) {
  int pid = fork();
  if (pid == 0) {
    printf("abc\n");
  }
  else { 
    wait(NULL);
    printf("def\n");
  }
  
  return 0;
}
