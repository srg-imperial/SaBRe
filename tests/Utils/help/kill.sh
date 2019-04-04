# REQUIRES: kill
# RUN: %{sbr} %{kill}         --help &>%t1
# RUN: grep "kill" %t1
