# REQUIRES: fuser
# RUN: %{sbr} %{fuser} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "fuser" %t1
