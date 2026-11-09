// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"

	"github.com/abundo/portitor/models"
)

// Entry-time checks. They cover shape and references; the full semantic
// check is fwconfig.Validate at deploy time (see builder.Build), which also
// runs again on the agent.

// presentInterface hides the tunnel broker update key.
func presentInterface(i *models.Interface) {
	i.HasHeUpdateKey = i.HeUpdateKey != ""
	i.NewHeUpdateKey = ""
}

// dnsName trims a host name entered with or without the trailing dot.
func dnsName(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}
