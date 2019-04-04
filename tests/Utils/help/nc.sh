# REQUIRES: nc
# RUN: %{sbr} %{nc}           -h     &>%t1
# RUN: grep "nc" %t1
