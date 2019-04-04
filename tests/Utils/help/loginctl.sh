# REQUIRES: loginctl
# RUN: %{sbr} %{loginctl}     --help &>%t1
# RUN: grep "loginctl" %t1
