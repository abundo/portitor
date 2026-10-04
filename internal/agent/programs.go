// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// program is an external command the agent runs, directly or through a
// systemd unit.
type program struct {
	name    string
	purpose string
	// needed reports whether an instance uses the program; nil means
	// every apply needs it.
	needed func(in *fwconfig.Instance) bool
}

var programs = []program{
	{name: "ip", purpose: "interfaces and routes (iproute2)"},
	{name: "tc", purpose: "traffic shaping (iproute2)"},
	{name: "nft", purpose: "firewall rules (nftables)"},
	{name: "sysctl", purpose: "forwarding settings (procps)"},
	{name: "systemctl", purpose: "service management (systemd)"},
	{name: "nsenter", purpose: "instance namespaces (util-linux)"},
	{name: "wg", purpose: "WireGuard (wireguard-tools)", needed: func(in *fwconfig.Instance) bool {
		for _, ifc := range in.Interfaces {
			if ifc.Kind == fwconfig.KindWireGuard {
				return true
			}
		}
		return false
	}},
	{name: "named", purpose: "DNS server (BIND 9)", needed: func(in *fwconfig.Instance) bool { return in.DNS.Enabled }},
	{name: "kea-dhcp4", purpose: "DHCPv4 server (Kea)", needed: func(in *fwconfig.Instance) bool { return in.DHCP.Enabled }},
	{name: "kea-dhcp6", purpose: "DHCPv6 server (Kea)", needed: func(in *fwconfig.Instance) bool { return len(render.DHCP6Subnets(in)) > 0 }},
	{name: "radvd", purpose: "router advertisements (radvd)", needed: func(in *fwconfig.Instance) bool { return len(in.RA) > 0 }},
	{name: "jool", purpose: "NAT64 (Jool)", needed: func(in *fwconfig.Instance) bool { return in.NAT64 != nil }},
	// FRR's daemons are in /usr/lib/frr, off the PATH; vtysh comes with them.
	{name: "vtysh", purpose: "BGP, OSPF, VRRP and BFD (FRR)", needed: func(in *fwconfig.Instance) bool { return in.FRRRunning() }},
}

// lookPath is exec.LookPath, replaceable in tests.
var lookPath = exec.LookPath

// programStatus reports where each program is installed. doc, when not
// nil, marks the ones its instances need.
func programStatus(doc *fwconfig.Document) []ProgramStatus {
	var exp fwconfig.Document
	if doc != nil {
		exp = doc.Expand()
	}
	out := make([]ProgramStatus, 0, len(programs))
	for _, p := range programs {
		ps := ProgramStatus{Name: p.name, Purpose: p.purpose}
		ps.Path, _ = lookPath(p.name)
		if doc != nil {
			ps.Needed = len(neededBy(&exp, p)) > 0
		}
		out = append(out, ps)
	}
	return out
}

// neededBy returns the instances of an expanded document that use p.
func neededBy(exp *fwconfig.Document, p program) []string {
	var names []string
	for i := range exp.Instances {
		if in := &exp.Instances[i]; p.needed == nil || p.needed(in) {
			names = append(names, in.Name)
		}
	}
	return names
}

// checkPrograms fails if a program the document needs is not installed,
// before anything on the system changes.
func checkPrograms(exp *fwconfig.Document) error {
	var missing []string
	for _, p := range programs {
		users := neededBy(exp, p)
		if len(users) == 0 {
			continue
		}
		if _, err := lookPath(p.name); err != nil {
			missing = append(missing, fmt.Sprintf("%s, for %s in instance %s", p.name, p.purpose, strings.Join(users, ", ")))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("programs not installed on the firewall: %s", strings.Join(missing, "; "))
	}
	return nil
}
