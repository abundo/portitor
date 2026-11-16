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

// GateFamilies are the families of the gate's second layer: tables named
// GateTable that hook the whole namespace, not a device, so the kernel
// can't detach them from a device that is made again or moved (6.12 does
// that to the netdev gate). They match the devices by name.
var GateFamilies = []string{"inet", "arp", "bridge"}

// GateSecondPriority runs the second layer ahead of defragmentation,
// conntrack, the raw chains (rpf, synproxy) and Jool.
const GateSecondPriority = -500

// Gate is the gate of one namespace, as one nft transaction: closed, the
// netdev table drops everything on devs but LLDP, and the second layer
// drops what comes in or goes out by any of cover (the devices and those
// stacked on them, fwconfig.Instance.GateCover) in prerouting, output and
// postrouting (inet), ARP's input and output, and on bridge ports. Open,
// the netdev table passes everything and the second layer is gone, so the
// active host's datapath has no hook more. It replaces the tables that are
// there, or adds them. It has no state of the host's in it but what the
// agent passes, as the agent loads it itself: open or closed is not
// configuration, and a preview must not depend on it.
func Gate(devs, cover []string, open bool) string {
	var b strings.Builder
	b.WriteString(GateNetdev(devs, open))
	for _, fam := range GateFamilies {
		b.WriteString(GateDelete(fam))
	}
	if open || len(devs) == 0 {
		return b.String()
	}
	if len(cover) == 0 {
		cover = devs
	}
	list := `{ "` + strings.Join(cover, `", "`) + `" }`
	chain := func(name, hook, match string) {
		fmt.Fprintf(&b, "\tchain %s {\n\t\ttype filter hook %s priority %d; policy accept;\n\t\t%s %s drop\n\t}\n",
			name, hook, GateSecondPriority, match, list)
	}
	fmt.Fprintf(&b, "table inet %s {\n", GateTable)
	chain("prerouting", "prerouting", "iifname")
	chain("output", "output", "oifname")
	chain("postrouting", "postrouting", "oifname")
	b.WriteString("}\n")
	fmt.Fprintf(&b, "table arp %s {\n", GateTable)
	chain("input", "input", "iifname")
	chain("output", "output", "oifname")
	b.WriteString("}\n")
	fmt.Fprintf(&b, "table bridge %s {\n", GateTable)
	fmt.Fprintf(&b, "\tchain prerouting {\n\t\ttype filter hook prerouting priority %d; policy accept;\n\t\tether type %s accept\n\t\tiifname %s drop\n\t}\n",
		GateSecondPriority, lldpEtherType, list)
	fmt.Fprintf(&b, "\tchain postrouting {\n\t\ttype filter hook postrouting priority %d; policy accept;\n\t\tether type %s accept\n\t\toifname %s drop\n\t}\n",
		GateSecondPriority, lldpEtherType, list)
	b.WriteString("}\n")
	return b.String()
}

// GateDelete removes the family's gate table, there or not.
func GateDelete(family string) string {
	// Adding the table first makes the delete safe when there is none.
	return fmt.Sprintf("table %s %s\ndelete table %s %s\n", family, GateTable, family, GateTable)
}

// GateNetdev is the netdev table alone: closed drops everything on devs
// but LLDP, open passes everything. The agent falls back to it when the
// kernel refuses the second layer, so a host can still close and open.
func GateNetdev(devs []string, open bool) string {
	var b strings.Builder
	b.WriteString(GateDelete("netdev"))
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
