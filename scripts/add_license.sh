#!/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Aryan Ameri
# SPDX-FileCopyrightText: 2026 Aryan Ameri <info@ameri.me>
#

LICENSE_HEADER='# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
'

# Find all .nim files and add header
# shellcheck disable=SC2312
find . -name "*.nim" -type f -print0 | while IFS= read -r -d '' file; do
  # Check if file already has the license header
  first_line=$(head -1 "${file}") || true
  if echo "${first_line}" | grep -q "SPDX-License-Identifier"; then
    echo "Skipping (already has header): ${file}"
  else
    echo "Adding header to: ${file}"
    # Create temp file with header + original content
    echo "${LICENSE_HEADER}" | cat - "${file}" >/tmp/nim_temp && mv /tmp/nim_temp "${file}"
  fi
done
