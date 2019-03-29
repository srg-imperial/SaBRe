# REQUIRES: dumpkeys
# RUN: %{sbr} %{dumpkeys} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "dumpkeys" %t1
