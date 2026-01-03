#!/bin/bash

LICENSE_HEADER='# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
'

# Find all .nim files and add header
find . -name "*.nim" -type f | while read -r file; do
    # Check if file already has the license header
    if head -1 "$file" | grep -q "SPDX-License-Identifier"; then
        echo "Skipping (already has header): $file"
    else
        echo "Adding header to: $file"
        # Create temp file with header + original content
        echo "$LICENSE_HEADER" | cat - "$file" > /tmp/nim_temp && mv /tmp/nim_temp "$file"
    fi
done
