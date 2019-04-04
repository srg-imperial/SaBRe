# REQUIRES: tar
# RUN: %{sbr} %{tar}          --help &>%t1
# RUN: grep "tar" %t1
