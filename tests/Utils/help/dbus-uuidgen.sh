# REQUIRES: dbus-uuidgen
# RUN: %{sbr} %{dbus-uuidgen} --help &>%t1
# RUN: grep "dbus-uuidgen" %t1
