# REQUIRES: ps
# RUN: %{sbr} %{ps}           --help s &>%t1
# RUN: grep "ps" %t1
