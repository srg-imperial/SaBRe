# REQUIRES: mount
# RUN: %{sbr} %{mount}        --help &>%t1
# RUN: grep "mount" %t1
