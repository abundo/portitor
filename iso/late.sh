#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# preseed/late_command: runs in the installer, with the new system on
# /target. The work happens inside it (target.sh).
set -e
rm -rf /target/tmp/portitor-iso
cp -r /cdrom/portitor /target/tmp/portitor-iso
in-target sh /tmp/portitor-iso/target.sh
rm -rf /target/tmp/portitor-iso
