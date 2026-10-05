// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"regexp"
	"strings"
	"unicode"
)

// Tunnel6in4 is a 6in4 tunnel (a Linux sit device, IP protocol 41): IPv6
// carried in IPv4 to Remote, as Hurricane Electric's tunnel broker
// (tunnelbroker.net) offers. The interface's addresses are its IPv6 end
// (the client address, 2001:470:x:y::2/64).
type Tunnel6in4 struct {
	// Remote is the tunnel server's IPv4 address.
	Remote string `json:"remote"`
	// Local is the firewall's IPv4 address of the tunnel; empty is any,
	// for an address that changes (a DHCP WAN) or is behind NAT.
	Local string `json:"local,omitempty"`
	// TunnelBroker, when set, tells the tunnel broker the firewall's
	// IPv4 address whenever it changes.
	TunnelBroker *TunnelBroker `json:"tunnel_broker,omitempty"`
}

// TunnelBroker is the account of a Hurricane Electric tunnel, for its
// endpoint update API (the dyndns2 protocol at ipv4.tunnelbroker.net).
type TunnelBroker struct {
	// TunnelID is the tunnel's id, a number (tunnelbroker.net's Tunnel ID).
	TunnelID string `json:"tunnel_id"`
	// Username is the tunnelbroker.net account's user name.
	Username string `json:"username"`
	// UpdateKey is the tunnel's update key (Advanced tab), or the
	// account's password. A secret.
	UpdateKey string `json:"update_key"`
}

// TunnelRouteMetric is the metric of the IPv6 default route through a 6in4
// tunnel: after a static ::/0 (metric 0), before one from router
// advertisements (1024).
const TunnelRouteMetric = 512

// Protocol6in4 is the IP protocol number of IPv6 in IPv4.
const Protocol6in4 = 41

var (
	tunnelIDRe = regexp.MustCompile(`^[0-9]{1,12}$`)
	heUserRe   = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)
)

// ValidTunnelID reports whether s is a tunnel broker tunnel id.
func ValidTunnelID(s string) bool { return tunnelIDRe.MatchString(s) }

// ValidTunnelUser reports whether s is a tunnel broker user name.
func ValidTunnelUser(s string) bool { return heUserRe.MatchString(s) }

// ValidUpdateKey reports whether s may be an update key: printable, no
// spaces.
func ValidUpdateKey(s string) bool {
	return s != "" && len(s) <= 128 && !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || !unicode.IsPrint(r) })
}

// ValidTunnelEndpoint reports whether s is a usable IPv4 tunnel endpoint
// (unicast, not loopback).
func ValidTunnelEndpoint(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func (v *validator) tunnel6in4(p string, ifc *Interface) {
	t := ifc.Tunnel
	if t == nil {
		v.addf("%s: 6in4 settings missing", p)
		return
	}
	if !ValidTunnelEndpoint(t.Remote) {
		v.addf("%s: invalid tunnel server address %q (IPv4)", p, t.Remote)
	}
	if t.Local != "" && !ValidTunnelEndpoint(t.Local) {
		v.addf("%s: invalid local address %q (IPv4)", p, t.Local)
	}
	if tb := t.TunnelBroker; tb != nil {
		if !ValidTunnelID(tb.TunnelID) {
			v.addf("%s: invalid tunnel broker tunnel id %q", p, tb.TunnelID)
		}
		if !ValidTunnelUser(tb.Username) {
			v.addf("%s: invalid tunnel broker user name %q", p, tb.Username)
		}
		if !ValidUpdateKey(tb.UpdateKey) {
			v.addf("%s: invalid tunnel broker update key", p)
		}
	}
}
