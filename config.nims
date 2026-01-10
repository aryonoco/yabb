# SPDX-License-Identifier: 0BSD
# Copyright (c) 2023-2026 Aryan Ameri
#
# begin Nimble config (version 2)
--noNimblePath
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
