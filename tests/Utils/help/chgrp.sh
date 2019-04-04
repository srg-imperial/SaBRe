# REQUIRES: chgrp
# RUN: %{sbr} %{chgrp}        --help &>%t1
# RUN: grep "chgrp" %t1
