// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import "net/netip"

// NTP is the instance's NTP client and server, run by chrony in its
// namespace. The default instance's chrony sets the host's clock; a virtual
// firewall's only keeps time (chronyd -x), as the clock is the host's.
type NTP struct {
	Servers []NTPServer `json:"servers"`
	// Interfaces answer NTP clients (the ruleset's auto input rule); none
	// serves no one.
	Interfaces []string `json:"interfaces,omitempty"`
	// Allow lists the client prefixes chrony answers on Interfaces; empty
	// answers any client there.
	Allow []string `json:"allow,omitempty"`
}

// NTPServer is a time source: an address or host name, or with Pool a
// name that resolves to several servers.
type NTPServer struct {
	Address string `json:"address"`
	Pool    bool   `json:"pool,omitempty"`
	IBurst  bool   `json:"iburst,omitempty"`
	// NTS authenticates the server (Network Time Security, RFC 8915).
	NTS bool `json:"nts,omitempty"`
}

// NTPPort is the port NTP clients send to.
const NTPPort = 123

// ValidNTPServer checks a time source's address or host name.
func ValidNTPServer(s string) bool {
	if _, err := ParseAddr(s); err == nil {
		return true
	}
	return hostRe.MatchString(s)
}

func (v *validator) ntp(p string, n *NTP, ifaces map[string]*Interface) {
	if len(n.Servers) == 0 {
		v.addf("%s: ntp: no servers", p)
	}
	seen := map[string]bool{}
	for _, s := range n.Servers {
		if !ValidNTPServer(s.Address) {
			v.addf("%s: ntp: invalid server %q", p, s.Address)
		}
		if seen[s.Address] {
			v.addf("%s: ntp: duplicate server %q", p, s.Address)
		}
		seen[s.Address] = true
	}
	for _, name := range n.Interfaces {
		if ifaces[name] == nil {
			v.addf("%s: ntp: unknown interface %q", p, name)
		}
	}
	for _, a := range n.Allow {
		if _, err := netip.ParsePrefix(a); err != nil {
			v.addf("%s: ntp: invalid allow prefix %q", p, a)
		}
	}
}
