// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
)

// Entry-time checks. They cover shape and references; the full semantic
// check is fwconfig.Validate at deploy time (see builder.Build), which also
// runs again on the agent.

// dnsName trims a host name entered with or without the trailing dot.
func dnsName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
