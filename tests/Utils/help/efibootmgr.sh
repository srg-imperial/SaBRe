# REQUIRES: efibootmgr
# RUN: %{sbr} %{efibootmgr}   --help &>%t1
# RUN: grep "efibootmgr" %t1
