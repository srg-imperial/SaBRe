# REQUIRES: dd
# RUN: %{sbr} %{dd}           --help &>%t1
# RUN: grep "dd" %t1
