// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// PolicyRouteChain marks the packets of the policy routes
// (fwconfig.PolicyRoute), after the NAT64 chain (NAT64Priority): a packet
// it marked is left alone.
const PolicyRouteChain = "prerouting_policy"

// writePolicyRoutes renders PolicyRouteChain: the first policy route that
// matches a packet gives it its mark (fwconfig.PolicyRouteMark), which the
// agent's rule looks up in the policy's table; an exception (no route)
// leaves it unmarked, to the main table.
func writePolicyRoutes(b *strings.Builder, in *fwconfig.Instance) {
	if len(in.PolicyRoutes) == 0 {
		return
	}
	b.WriteString("\tchain " + PolicyRouteChain + " {\n")
	fmt.Fprintf(b, "\t\ttype filter hook prerouting priority %s + 1; policy accept;\n", NAT64Priority)
	b.WriteString("\t\tmeta mark != 0 return\n")
	for i, p := range in.PolicyRoutes {
		what := fmt.Sprintf("policy route %d", i+1)
		// At prerouting a VRF's member is still the input interface;
		// policy routes have none (Validate).
		alts, ok := ifaceMatch(b, what, in, p.InInterfaces, nil, false)
		if !ok {
			continue
		}
		tail := []string{"counter"}
		desc := p.Description
		if p.Routed() {
			tail = append(tail, fmt.Sprintf("meta mark set %#x", fwconfig.PolicyRouteMark(i)))
		} else if desc == "" {
			desc = "main table"
		}
		tail = append(tail, "accept", comment(what, desc))
		for _, parts := range alts {
			for _, m := range p.Matches() {
				var ok bool
				if m.FamilyMatch, ok = dropEmptySets(in, m.FamilyMatch); !ok {
					continue
				}
				for _, match := range matchExprs(m.FamilyMatch, serviceExpr(m.Service)) {
					line := append(append(append([]string(nil), parts...), match...), tail...)
					b.WriteString("\t\t" + strings.Join(line, " ") + "\n")
				}
			}
		}
	}
	b.WriteString("\t}\n\n")
}

// writePolicyRouteUnmark clears the policy routes' marks in the forward
// chain, once the packet is routed: a shaper marks only unmarked packets.
func writePolicyRouteUnmark(b *strings.Builder, in *fwconfig.Instance) {
	for _, p := range in.PolicyRoutes {
		if p.Routed() {
			fmt.Fprintf(b, "\t\tmeta mark & %#x == %#x meta mark set 0 comment \"policy routes\"\n",
				^uint32(fwconfig.MaxPolicyRoutes-1), fwconfig.PolicyRouteMarkBase)
			return
		}
	}
}
