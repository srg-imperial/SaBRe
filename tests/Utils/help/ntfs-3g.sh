# REQUIRES: ntfs-3g
# RUN: %{sbr} %{ntfs-3g} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 9
# RUN: grep "Usage:    ntfs-3g" %t1
