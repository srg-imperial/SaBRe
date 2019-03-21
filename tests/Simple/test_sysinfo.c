/*
 * RUN: %{cc} %s -o %t1
 * RUN: %{vx} %t1 &> %t1.actual
 * RUN: echo "Success"  >  %t1.expected
 * RUN: diff %t1.actual %t1.expected
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include <sys/sysinfo.h>

int main(int argc, char ** argv) {

  struct sysinfo info;

  int ret = sysinfo(&info);

  assert(!ret);

  char buf[1024];

  // Read each field of info
  // Make sure leader and follower get the same value by using syscall open
  // If the follower gets a different value, open will diverge and the test will fail
  snprintf(buf, 1024, "%ld", info.uptime);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld.%ld.%ld", info.loads[0], info.loads[1], info.loads[2]);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld.%ld.", info.totalram, info.freeram);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld.%ld", info.sharedram, info.bufferram);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld.%ld", info.totalswap, info.freeswap);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld", info.procs);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld.%ld", info.totalhigh, info.freehigh);
  open(buf, O_RDONLY);

  snprintf(buf, 1024, "%ld", info.mem_unit);
  open(buf, O_RDONLY);

  printf("Success\n");

  return 0;
}
