# REQUIRES: chacl
# RUN: %{sbr} %{chacl} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "chacl" %t1
