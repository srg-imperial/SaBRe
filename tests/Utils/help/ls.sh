# REQUIRES: ls
# RUN: %{sbr} %{ls}           --help &>%t1
# RUN: grep "ls" %t1
