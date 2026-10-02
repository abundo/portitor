// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// JoinPrefix starts a join string: what portitor-setup prints on a firewall
// set up for the agent only, for `portitor-web bootstrap --join` on the
// portitor-web host.
const JoinPrefix = "portitor-join:"

// joinData is the join string's JSON, base64url-encoded after JoinPrefix.
type joinData struct {
	URL         string   `json:"url"`
	Token       string   `json:"token"`
	Fingerprint string   `json:"fingerprint"`
	LAN         string   `json:"lan"`
	Address     string   `json:"address"`
	WAN         string   `json:"wan,omitempty"`
	WANAddress  string   `json:"wan_address,omitempty"`
	Gateway     string   `json:"gateway,omitempty"`
	DHCPRange   string   `json:"dhcp_range,omitempty"`
	DHCPDNS     []string `json:"dhcp_dns,omitempty"`
}

// ParseJoin decodes a join string into bootstrap options for a firewall
// whose agent runs on another host: no GUI port is opened there.
func ParseJoin(s string) (BootstrapOptions, error) {
	var o BootstrapOptions
	// Line breaks and spaces from copying off a terminal.
	s = strings.Join(strings.Fields(s), "")
	rest, ok := strings.CutPrefix(s, JoinPrefix)
	if !ok {
		return o, fmt.Errorf("a join string starts with %s", JoinPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(rest, "="))
	if err != nil {
		return o, errors.New("the join string is damaged (base64); copy it again")
	}
	var d joinData
	if err := json.Unmarshal(raw, &d); err != nil {
		return o, errors.New("the join string is damaged (JSON); copy it again")
	}
	if !strings.HasPrefix(d.URL, "https://") || d.Token == "" || d.Fingerprint == "" {
		return o, errors.New("the join string lacks the agent URL, token or fingerprint")
	}
	o = BootstrapOptions{AgentURL: d.URL, AgentToken: d.Token, AgentFingerprint: d.Fingerprint, LAN: d.LAN, WAN: d.WAN}
	if o.Address, err = netip.ParsePrefix(d.Address); err != nil {
		return o, fmt.Errorf("join string: LAN address: %w", err)
	}
	if d.WANAddress != "" {
		if o.WANAddress, err = netip.ParsePrefix(d.WANAddress); err != nil {
			return o, fmt.Errorf("join string: WAN address: %w", err)
		}
	}
	if d.Gateway != "" {
		if o.Gateway, err = netip.ParseAddr(d.Gateway); err != nil {
			return o, fmt.Errorf("join string: gateway: %w", err)
		}
	}
	if d.DHCPRange != "" {
		if o.DHCPStart, o.DHCPEnd, err = ParseDHCPRange(d.DHCPRange); err != nil {
			return o, fmt.Errorf("join string: DHCP range: %w", err)
		}
	}
	for _, a := range d.DHCPDNS {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return o, fmt.Errorf("join string: DHCP DNS server: %w", err)
		}
		o.DHCPDNS = append(o.DHCPDNS, ip)
	}
	return o, nil
}

// ParseDHCPRange parses "192.168.1.100-192.168.1.199".
func ParseDHCPRange(s string) (start, end netip.Addr, err error) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return start, end, errors.New("start-end, e.g. 192.168.1.100-192.168.1.199")
	}
	if start, err = netip.ParseAddr(strings.TrimSpace(a)); err != nil {
		return start, end, err
	}
	end, err = netip.ParseAddr(strings.TrimSpace(b))
	return start, end, err
}
