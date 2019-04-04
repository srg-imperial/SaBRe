# REQUIRES: ln
# RUN: %{sbr} %{ln}           --help &>%t1
# RUN: grep "ln" %t1
