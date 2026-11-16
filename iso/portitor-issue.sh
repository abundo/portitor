#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Keeps the host's interfaces and their addresses on the console's login
# screen (/run/issue.d, which agetty reads with /etc/issue.d), rewritten when an
# address or link changes. Run by portitor-issue.service. A virtual firewall's
# interfaces are in its namespace and not listed.
set -u
out=/run/issue.d/50-portitor-interfaces.issue
mkdir -p /run/issue.d

update() {
	local tmp=$out.tmp
	{
		echo "Interfaces:"
		# agetty reads backslashes as escapes; interface names have none.
		ip -br address show | awk '$1 != "lo" { printf "  %-16s %-8s", $1, $2; for (i = 3; i <= NF; i++) printf " %s", $i; print "" }' | tr -d '\\'
		echo
	} >"$tmp" && mv -f "$tmp" "$out"
	# A login prompt already shown prints the issue again.
	agetty --reload 2>/dev/null || true
}

update
ip monitor address link | while read -r _; do
	# One change is a burst of events: wait until they stop.
	while read -r -t 1 _; do :; done
	update
done
