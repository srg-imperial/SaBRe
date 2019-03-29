# REQUIRES: lsmod
# RUN: %{sbr} %{lsmod} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "lsmod" %t1
