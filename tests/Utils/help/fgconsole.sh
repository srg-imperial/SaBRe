# REQUIRES: fgconsole
# RUN: %{sbr} %{fgconsole} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "fgconsole" %t1
