# REQUIRES: grep
# RUN: %{sbr} %{grep}         --help &>%t1
# RUN: grep "grep" %t1
