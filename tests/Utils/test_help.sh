# RUN: %{sbr} %{cc} --help &>%t1
# RUN: grep "gcc" %t1

# RUN: %{sbr} %{bunzip2}      --help &>%t1
# RUN: grep "bunzip2" %t1
# RUN: %{sbr} %{bzip2}        --help &>%t1
# RUN: grep "bzip2" %t1
# RUN: %{sbr} %{cat}          --help &>%t1
# RUN: grep "cat" %t1
# RUN: %{sbr} %{chgrp}        --help &>%t1
# RUN: grep "chgrp" %t1
# RUN: %{sbr} %{chmod}        --help &>%t1
# RUN: grep "chmod" %t1
# RUN: %{sbr} %{cp}           --help &>%t1
# RUN: grep "cp" %t1
# RUN: %{sbr} %{date}         --help &>%t1
# RUN: grep "date" %t1
# RUN: %{sbr} %{dbus-uuidgen} --help &>%t1
# RUN: grep "dbus-uuidgen" %t1
# RUN: %{sbr} %{dd}           --help &>%t1
# RUN: grep "dd" %t1
# RUN: %{sbr} %{dmesg}        --help &>%t1
# RUN: grep "dmesg" %t1
# RUN: %{sbr} %{ed}           --help &>%t1
# RUN: grep "ed" %t1
# RUN: %{sbr} %{efibootmgr}   --help &>%t1
# RUN: grep "efibootmgr" %t1
# RUN: %{sbr} %{grep}         --help &>%t1
# RUN: grep "grep" %t1
# RUN: %{sbr} %{gzip}         --help &>%t1
# RUN: grep "gzip" %t1
# RUN: %{sbr} %{kill}         --help &>%t1
# RUN: grep "kill" %t1
# RUN: %{sbr} %{lessecho}     --help &>%t1
# RUN: grep "lessecho" %t1
# RUN: %{sbr} %{ln}           --help &>%t1
# RUN: grep "ln" %t1
# RUN: %{sbr} %{loginctl}     --help &>%t1
# RUN: grep "loginctl" %t1
# RUN: %{sbr} %{ls}           --help &>%t1
# RUN: grep "ls" %t1
# RUN: %{sbr} %{mount}        --help &>%t1
# RUN: grep "mount" %t1
# RUN: %{sbr} %{nano}         --help &>%t1
# RUN: grep "nano" %t1
# RUN: %{sbr} %{nc}           -h     &>%t1
# RUN: grep "nc" %t1
# RUN: %{sbr} %{openvt}       --help &>%t1
# RUN: grep "openvt" %t1
# RUN: %{sbr} %{ps}           --help s &>%t1
# RUN: grep "ps" %t1
# RUN: %{sbr} %{sed}          --help &>%t1
# RUN: grep "sed" %t1
# RUN: %{sbr} %{setfacl}      --help &>%t1
# RUN: grep "setfacl" %t1
# RUN: %{sbr} %{tar}          --help &>%t1
# RUN: grep "tar" %t1
# RUN: %{sbr} %{mktemp}       --help &>%t1
# RUN: grep "mktemp" %t1

# Some utils return non-zero when called with -h

# RUN: %{sbr} %{chacl} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "chacl" %t1

# RUN: %{sbr} %{dumpkeys} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "dumpkeys" %t1

# RUN: %{sbr} %{fgconsole} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "fgconsole" %t1

# RUN: %{sbr} %{fuser} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "fuser" %t1

# RUN: %{sbr} %{ip} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 255
# RUN: grep "ip" %t1

# RUN: %{sbr} %{ping} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 2
# RUN: grep "ping" %t1

# Failed due to Position-Independent Executable (fixed in e39ed762):
# RUN: %{sbr} %{bash} --help &>%t1
# RUN: grep "bash" %t1

# RUN: %{sbr} %{kmod} --help &>%t1
# RUN: grep "kmod" %t1

# RUN: %{sbr} %{lsmod} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 1
# RUN: grep "lsmod" %t1

# Exit code is the non-standard 9
# RUN: %{sbr} %{ntfs-3g} --help &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 9
# RUN: grep "Usage:    ntfs-3g" %t1
