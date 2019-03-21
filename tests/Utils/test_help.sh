# RUN: %{vx} %{cc} --help &>%t1
# RUN: grep "gcc" %t1

# RUN: %{vx} %{bunzip2}      --help &>%t1
# RUN: grep "bunzip2" %t1
# RUN: %{vx} %{bzip2}        --help &>%t1
# RUN: grep "bzip2" %t1
# RUN: %{vx} %{cat}          --help &>%t1
# RUN: grep "cat" %t1
# RUN: %{vx} %{chgrp}        --help &>%t1
# RUN: grep "chgrp" %t1
# RUN: %{vx} %{chmod}        --help &>%t1
# RUN: grep "chmod" %t1
# RUN: %{vx} %{cp}           --help &>%t1
# RUN: grep "cp" %t1
# RUN: %{vx} %{date}         --help &>%t1
# RUN: grep "date" %t1
# RUN: %{vx} %{dbus-uuidgen} --help &>%t1
# RUN: grep "dbus-uuidgen" %t1
# RUN: %{vx} %{dd}           --help &>%t1
# RUN: grep "dd" %t1
# RUN: %{vx} %{dmesg}        --help &>%t1
# RUN: grep "dmesg" %t1
# RUN: %{vx} %{ed}           --help &>%t1
# RUN: grep "ed" %t1
# RUN: %{vx} %{efibootmgr}   --help &>%t1
# RUN: grep "efibootmgr" %t1
# RUN: %{vx} %{grep}         --help &>%t1
# RUN: grep "grep" %t1
# RUN: %{vx} %{gzip}         --help &>%t1
# RUN: grep "gzip" %t1
# RUN: %{vx} %{kill}         --help &>%t1
# RUN: grep "kill" %t1
# RUN: %{vx} %{lessecho}     --help &>%t1
# RUN: grep "lessecho" %t1
# RUN: %{vx} %{ln}           --help &>%t1
# RUN: grep "ln" %t1
# RUN: %{vx} %{loginctl}     --help &>%t1
# RUN: grep "loginctl" %t1
# RUN: %{vx} %{ls}           --help &>%t1
# RUN: grep "ls" %t1
# RUN: %{vx} %{mount}        --help &>%t1
# RUN: grep "mount" %t1
# RUN: %{vx} %{nano}         --help &>%t1
# RUN: grep "nano" %t1
# RUN: %{vx} %{nc}           -h     &>%t1
# RUN: grep "nc" %t1
# RUN: %{vx} %{openvt}       --help &>%t1
# RUN: grep "openvt" %t1
# RUN: %{vx} %{ps}           --help s &>%t1
# RUN: grep "ps" %t1
# RUN: %{vx} %{sed}          --help &>%t1
# RUN: grep "sed" %t1
# RUN: %{vx} %{setfacl}      --help &>%t1
# RUN: grep "setfacl" %t1
# RUN: %{vx} %{tar}          --help &>%t1
# RUN: grep "tar" %t1
# RUN: %{vx} %{mktemp}       --help &>%t1
# RUN: grep "mktemp" %t1

# Some utils return non-zero when called with -h

# RUN: %{vx} %{chacl} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "chacl" %t1

# RUN: %{vx} %{dumpkeys} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "dumpkeys" %t1

# RUN: %{vx} %{fgconsole} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "fgconsole" %t1

# RUN: %{vx} %{fuser} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "fuser" %t1

# RUN: %{vx} %{ip} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 255
# RUN: grep "ip" %t1

# RUN: %{vx} %{ping} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 2
# RUN: grep "ping" %t1

# Failed due to Position-Independent Executable (fixed in e39ed762):
# RUN: %{vx} %{bash} --help &>%t1
# RUN: grep "bash" %t1

# RUN: %{vx} %{kmod} --help &>%t1
# RUN: grep "kmod" %t1

# RUN: %{vx} %{lsmod} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "lsmod" %t1

# Exit code is the non-standard 9
# RUN: %{vx} %{ntfs-3g} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 9
# RUN: grep "Usage:    ntfs-3g" %t1
