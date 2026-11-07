// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dhcpd is Portitor's DHCPv4 and DHCPv6 server, one process per
// instance (portitor-agent dhcpd, in the instance's namespace, as an
// unprivileged user). It serves what Kea served: pools, the gateway, DNS
// servers and domain, option 108, MAC reservations, and several subnets on
// one interface. Its leases are an append-only log in its own directory;
// the agent reads them, and later sets its mode, through a Unix socket.
package dhcpd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

// Config is dhcpd.json, rendered by internal/render from the document.
type Config struct {
	Instance string `json:"instance"`
	// LeaseTime is the valid lifetime, in seconds.
	LeaseTime int    `json:"lease_time"`
	Domain    string `json:"domain,omitempty"`
	// DUID is the DHCPv6 server's DUID, in hex: the same on both hosts of
	// an HA pair, so a renewal reaches either.
	DUID     string    `json:"duid,omitempty"`
	Subnets4 []Subnet4 `json:"subnets4,omitempty"`
	Subnets6 []Subnet6 `json:"subnets6,omitempty"`
}

// Range is a pool's first and last address.
type Range struct {
	Start netip.Addr `json:"start"`
	End   netip.Addr `json:"end"`
}

// Contains says whether a is in the range.
func (r Range) Contains(a netip.Addr) bool {
	return r.Start.Compare(a) <= 0 && a.Compare(r.End) <= 0
}

// Reservation gives MAC its address, with a host name.
type Reservation struct {
	MAC      string     `json:"mac"`
	Addr     netip.Addr `json:"addr"`
	Hostname string     `json:"hostname,omitempty"`
}

// Subnet4 is a DHCPv4 subnet served on Interface. Its server id is the
// interface's address in it, shared by an HA pair's hosts.
type Subnet4 struct {
	Interface       string        `json:"interface"`
	Prefix          netip.Prefix  `json:"prefix"`
	ServerID        netip.Addr    `json:"server_id"`
	Pools           []Range       `json:"pools,omitempty"`
	Router          netip.Addr    `json:"router,omitzero"`
	DNS             []netip.Addr  `json:"dns,omitempty"`
	V6OnlyPreferred int           `json:"v6only_preferred,omitempty"`
	Reservations    []Reservation `json:"reservations,omitempty"`
}

// Subnet6 is a DHCPv6 subnet served on Interface (IA_NA addresses).
type Subnet6 struct {
	Interface    string        `json:"interface"`
	Prefix       netip.Prefix  `json:"prefix"`
	Pools        []Range       `json:"pools,omitempty"`
	DNS          []netip.Addr  `json:"dns,omitempty"`
	Reservations []Reservation `json:"reservations,omitempty"`
}

// LoadConfig reads dhcpd.json.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := ParseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// ParseConfig reads dhcpd.json's content.
func ParseConfig(b []byte) (*Config, error) {
	// A first line starting with // is a comment (the renderer's mark).
	if bytes.HasPrefix(b, []byte("//")) {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.LeaseTime <= 0 {
		c.LeaseTime = 86400
	}
	return &c, nil
}

// Interfaces are the interfaces with a subnet of the IP version.
func (c *Config) Interfaces(v6 bool) []string {
	var out []string
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if v6 {
		for _, s := range c.Subnets6 {
			add(s.Interface)
		}
	} else {
		for _, s := range c.Subnets4 {
			add(s.Interface)
		}
	}
	return out
}
