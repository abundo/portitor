// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"github.com/abundo/portitor/models"
)

// SNMP, per instance: the instance's snmp_* fields (prepareInstanceSNMP),
// its interfaces' snmp_serve, and its SNMPv3 users. The community and the
// users' passwords are write-only.

func presentInstance(in *models.Instance) {
	in.HasSnmpCommunity = in.SnmpCommunity != ""
	in.NewSnmpCommunity, in.ClearSnmpCommunity = "", false
}
