# These tests are for testing the existence of: unlinkat, faccessat and
# newfstatat system call.
#
# RUN: echo > %t1.file
# RUN: echo > %t2.file
# RUN: mkdir -p %t3.dir
# RUN: %{vx} /bin/rm %t1.file
# RUN: %{vx} /bin/rm -f %t2.file
# RUN: %{vx} /bin/rm -rf %t3.dir
