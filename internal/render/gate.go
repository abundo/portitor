// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"strings"
)

// GateTable is the netdev table that closes an HA standby's traffic
// interfaces (fwconfig.Instance.GateDevices). It is separate from the
// `inet firewall` table, so a commit leaves it alone.
const GateTable = "portitor_gate"

// GatePriority runs the gate ahead of anything else on the device.
const GatePriority = -500

// lldpEtherType stays open, so the standby keeps its neighbours and they
// keep theirs.
const lldpEtherType = "0x88cc"

// Gate is the gate of one namespace, as one nft transaction: closed drops
// everything on devs but LLDP, open passes everything. It replaces the
// table that is there, or adds it. It has no state of the host's in it
// but what the agent passes, as the agent loads it itself: open or closed
// is not configuration, and a preview must not depend on it.
func Gate(devs []string, open bool) string {
	var b strings.Builder
	// Adding the table first makes the delete safe when there is none.
	fmt.Fprintf(&b, "table netdev %s\ndelete table netdev %s\n", GateTable, GateTable)
	if len(devs) == 0 {
		return b.String()
	}
	list := `"` + strings.Join(devs, `", "`) + `"`
	policy := "drop"
	if open {
		policy = "accept"
	}
	fmt.Fprintf(&b, "table netdev %s {\n", GateTable)
	for _, hook := range []string{"ingress", "egress"} {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s devices = { %s } priority %d; policy %s;\n\t\tether type %s accept\n\t}\n",
			hook, hook, list, GatePriority, policy, lldpEtherType)
	}
	b.WriteString("}\n")
	return b.String()
}
