# REQUIRES: setfacl
# RUN: %{sbr} %{setfacl}      --help &>%t1
# RUN: grep "setfacl" %t1
