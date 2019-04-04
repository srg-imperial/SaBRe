# REQUIRES: kmod
# RUN: %{sbr} %{kmod} --help &>%t1
# RUN: grep "kmod" %t1
