# REQUIRES: dmesg
# RUN: %{sbr} %{dmesg}        --help &>%t1
# RUN: grep "dmesg" %t1
