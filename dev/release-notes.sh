#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Portitor contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# Print a release's section of CHANGELOG.md (without its heading), the
# release notes GoReleaser publishes. Fails when the tag has no section.
#
#   dev/release-notes.sh v0.5.1 > notes.md
set -euo pipefail

tag=${1:?usage: release-notes.sh <tag>}
notes=$(awk -v h="## $tag" '
	$0 == h { on = 1; next }
	on && /^## / { exit }
	on { print }
' "$(dirname "$0")/../CHANGELOG.md")

if [ -z "$(echo "$notes" | tr -d '[:space:]')" ]; then
	echo "CHANGELOG.md has no section \"## $tag\"" >&2
	exit 1
fi
# Without the blank lines around the section, and with each list item's
# wrapped lines joined: GitHub shows a release's line breaks as they are.
echo "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}' |
	awk '/^  [^ ]/ && prev != "" { sub(/^ +/, ""); prev = prev " " $0; next }
		{ if (started) print prev; prev = $0; started = 1 }
		END { if (started) print prev }'
