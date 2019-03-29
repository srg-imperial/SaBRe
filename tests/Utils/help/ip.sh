# REQUIRES: ip
# RUN: %{sbr} %{ip} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 255
# RUN: grep "ip" %t1
