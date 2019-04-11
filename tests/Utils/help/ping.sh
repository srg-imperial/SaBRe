# Copyright © 2019 Software Reliability Group, Imperial College London
#
# This file is part of SaBRe.
#
# SPDX-License-Identifier: GPL-3.0-or-later

# REQUIRES: ping
# RUN: %{sbr} %{ping} &>%t1 || RC=$(echo $?)
# RUN: test ${RC} -eq 2
# RUN: grep "ping" %t1
