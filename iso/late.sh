#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# preseed/late_command: runs in the installer, with the new system on
# /target. The work happens inside it (target.sh). The package repository
# (repo/, about a gigabyte) is not copied: it is mounted where target.sh looks
# for it.
set -e
d=/target/tmp/portitor-iso
rm -rf "$d"
mkdir -p "$d/repo"
for f in /cdrom/portitor/*; do
	[ "$f" = /cdrom/portitor/repo ] || cp -r "$f" "$d/"
done
mount -o bind /cdrom/portitor/repo "$d/repo"
status=0
in-target sh /tmp/portitor-iso/target.sh || status=$?
umount "$d/repo" || true
rm -rf "$d"
exit $status
