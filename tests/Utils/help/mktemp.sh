# REQUIRES: mktemp
# RUN: %{sbr} %{mktemp}       --help &>%t1
# RUN: grep "mktemp" %t1
