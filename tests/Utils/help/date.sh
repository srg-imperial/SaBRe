# REQUIRES: date
# RUN: %{sbr} %{date}         --help &>%t1
# RUN: grep "date" %t1
