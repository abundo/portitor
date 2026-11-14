// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// MaxResolverServers is as many nameservers as the C library reads.
const MaxResolverServers = 3

// Resolver is the host's own resolver (the default instance's
// /etc/resolv.conf): the DNS servers of the DHCP lease on DHCPInterface
// (an IPv4 DHCP client interface) while it has any, else Servers. The file
// is not written while there is nothing to put in it.
type Resolver struct {
	Servers       []string `json:"servers,omitempty"`
	DHCPInterface string   `json:"dhcp_interface,omitempty"`
}

func (v *validator) resolver(p string, in *Instance, ifaces map[string]*Interface) {
	r := in.Resolver
	if !in.Default {
		v.addf("%s: resolver: only the default instance has the host's resolver", p)
		return
	}
	if len(r.Servers) == 0 && r.DHCPInterface == "" {
		v.addf("%s: resolver: needs DNS servers or a DHCP interface", p)
	}
	if len(r.Servers) > MaxResolverServers {
		v.addf("%s: resolver: at most %d DNS servers", p, MaxResolverServers)
	}
	for _, s := range r.Servers {
		if _, err := ParseAddr(s); err != nil {
			v.addf("%s: resolver: invalid DNS server %q", p, s)
		}
	}
	if r.DHCPInterface != "" {
		switch ifc := ifaces[r.DHCPInterface]; {
		case ifc == nil:
			v.addf("%s: resolver: unknown DHCP interface %q", p, r.DHCPInterface)
		case ifc.IPv4Mode != ModeDHCP:
			v.addf("%s: resolver: interface %s is not a DHCP client", p, r.DHCPInterface)
		}
	}
}
