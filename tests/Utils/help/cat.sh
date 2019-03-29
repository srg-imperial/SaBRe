# REQUIRES: cat
# RUN: %{sbr} %{cat}          --help &>%t1
# RUN: grep "cat" %t1
