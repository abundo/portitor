// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"fmt"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// RPFChain drops what fails the interfaces' reverse path check
// (fwconfig.Interface.RPF), at priority raw: before conntrack, so a
// spoofed packet takes no connection. It sees a VRF's members as they
// are, before the VRF device: the lookup by the input interface is in its
// VRF's table.
const RPFChain = "prerouting_rpf"

// ChainPrerouting names RPFChain's drop counter (DropCounter, DropRPF).
const ChainPrerouting = "prerouting"

// rpfInterfaces are the enabled interfaces with the reverse path check
// and their OpenVPN TCP devices, which route their clients themselves.
func rpfInterfaces(in *fwconfig.Instance) []string {
	var names []string
	for _, ifc := range in.Interfaces {
		if ifc.RPF && ifc.Enabled {
			names = append(names, ifc.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return in.AddOpenVPNDevices(names)
}

// writeRPF renders RPFChain: a packet from a source the instance routes
// out by another interface than the one it came in on, or doesn't route
// at all, is dropped (fib saddr . iif). A virtual router's device has no
// routes: what comes in on it must route back by its interface (not in a
// VRF, Validate). Unspecified sources (DHCP's discover, IPv6's duplicate
// address detection) and the neighbour discovery a host needs before it
// has routes pass.
func writeRPF(b *strings.Builder, in *fwconfig.Instance) {
	ifs := rpfInterfaces(in)
	if len(ifs) == 0 {
		return
	}
	drop := fmt.Sprintf("counter name %q drop comment \"reverse path\"", DropCounter(ChainPrerouting, DropRPF))
	fmt.Fprintf(b, "\tchain %s {\n", RPFChain)
	b.WriteString("\t\ttype filter hook prerouting priority raw; policy accept;\n")
	b.WriteString("\t\tip saddr 0.0.0.0 return\n")
	b.WriteString("\t\tip6 saddr :: return\n")
	b.WriteString("\t\ticmpv6 type { nd-router-advert, nd-neighbor-solicit } return\n")
	fmt.Fprintf(b, "\t\tiifname %s fib saddr . iif oif missing %s\n", quotedSet(ifs), drop)
	for _, d := range in.VRRPDevices() {
		if slices.Contains(ifs, d.Parent) {
			fmt.Fprintf(b, "\t\tiifname %q fib saddr oifname != %q %s\n", d.Name, d.Parent, drop)
		}
	}
	b.WriteString("\t}\n\n")
}
