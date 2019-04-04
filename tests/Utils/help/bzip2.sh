# REQUIRES: bzip2
# RUN: %{sbr} %{bzip2}        --help &>%t1
# RUN: grep "bzip2" %t1
