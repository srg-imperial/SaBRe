# REQUIRES: ping
# RUN: %{sbr} %{ping} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 2
# RUN: grep "ping" %t1
