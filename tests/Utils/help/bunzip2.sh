# REQUIRES: bunzip2
# RUN: %{sbr} %{bunzip2}      --help &>%t1
# RUN: grep "bunzip2" %t1
