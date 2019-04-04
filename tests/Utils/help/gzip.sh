# REQUIRES: gzip
# RUN: %{sbr} %{gzip}         --help &>%t1
# RUN: grep "gzip" %t1
