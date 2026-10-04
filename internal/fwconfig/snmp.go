// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// SNMP is the instance's SNMP agent, net-snmp's snmpd in its namespace, so
// management platforms can monitor it: read-only, the whole MIB tree it
// has (system, interfaces, IP, host resources). A virtual firewall's sees
// its own interfaces.
type SNMP struct {
	Location string `json:"location,omitempty"`
	Contact  string `json:"contact,omitempty"`
	// Interfaces answer SNMP requests (the ruleset's auto input rule);
	// none answers no one.
	Interfaces []string `json:"interfaces,omitempty"`
	// Allow lists the client prefixes answered on Interfaces; empty
	// answers any client there.
	Allow []string `json:"allow,omitempty"`
	// Community is the SNMPv2c read-only community; empty: no SNMPv2c.
	Community string     `json:"community,omitempty"`
	Users     []SNMPUser `json:"users,omitempty"`
}

// SNMPUser is a read-only SNMPv3 user (USM). With PrivProtocol empty the
// user authenticates only (authNoPriv); otherwise it also encrypts
// (authPriv).
type SNMPUser struct {
	Name         string `json:"name"`
	AuthProtocol string `json:"auth_protocol"`
	AuthPassword string `json:"auth_password"`
	PrivProtocol string `json:"priv_protocol,omitempty"`
	PrivPassword string `json:"priv_password,omitempty"`
}

// SNMPPort is the port SNMP requests come to.
const SNMPPort = 161

// SNMPAuthProtocols and SNMPPrivProtocols are what an SNMPv3 user may use,
// in net-snmp's words. MD5 and DES are left out: broken.
var (
	SNMPAuthProtocols = []string{"SHA", "SHA-256", "SHA-512"}
	SNMPPrivProtocols = []string{"AES"}
)

var (
	// snmpSecretRe: printable ASCII without spaces, quotes, # or \, which
	// snmpd.conf would read as something else.
	snmpSecretRe   = regexp.MustCompile(`^[!$-&(-\[\]-~]+$`)
	snmpUserRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
	snmpTextBadsRe = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// CheckSNMPCommunity checks an SNMPv2c community.
func CheckSNMPCommunity(s string) string {
	if len(s) > 64 || !snmpSecretRe.MatchString(s) {
		return "the community must be 1 to 64 characters, without spaces, quotes, # or \\"
	}
	return ""
}

// CheckSNMPUser checks an SNMPv3 user; it returns its problems.
func CheckSNMPUser(u SNMPUser) []string {
	var out []string
	if !snmpUserRe.MatchString(u.Name) {
		out = append(out, "user name must be 1 to 32 letters, digits, '.', '_' or '-'")
	}
	if !slices.Contains(SNMPAuthProtocols, u.AuthProtocol) {
		out = append(out, "authentication protocol must be one of "+strings.Join(SNMPAuthProtocols, ", "))
	}
	pw := func(what, s string) {
		// net-snmp refuses passphrases shorter than 8.
		if len(s) < 8 || len(s) > 64 || !snmpSecretRe.MatchString(s) {
			out = append(out, what+" password must be 8 to 64 characters, without spaces, quotes, # or \\")
		}
	}
	pw("authentication", u.AuthPassword)
	switch {
	case u.PrivProtocol == "":
		if u.PrivPassword != "" {
			out = append(out, "privacy password without a privacy protocol")
		}
	case !slices.Contains(SNMPPrivProtocols, u.PrivProtocol):
		out = append(out, "privacy protocol must be one of "+strings.Join(SNMPPrivProtocols, ", "))
	default:
		pw("privacy", u.PrivPassword)
	}
	return out
}

// CheckSNMPText checks a location or contact: one line.
func CheckSNMPText(s string) bool {
	return len(s) <= 255 && !snmpTextBadsRe.MatchString(s)
}

func (v *validator) snmp(p string, s *SNMP, ifaces map[string]*Interface) {
	if s.Community == "" && len(s.Users) == 0 {
		v.addf("%s: snmp: no community and no users", p)
	}
	if s.Community != "" {
		if e := CheckSNMPCommunity(s.Community); e != "" {
			v.addf("%s: snmp: %s", p, e)
		}
	}
	if !CheckSNMPText(s.Location) || !CheckSNMPText(s.Contact) {
		v.addf("%s: snmp: location and contact must be one line", p)
	}
	seen := map[string]bool{}
	for _, u := range s.Users {
		for _, e := range CheckSNMPUser(u) {
			v.addf("%s: snmp user %q: %s", p, u.Name, e)
		}
		if seen[u.Name] {
			v.addf("%s: snmp: duplicate user %q", p, u.Name)
		}
		seen[u.Name] = true
	}
	for _, name := range s.Interfaces {
		if ifaces[name] == nil {
			v.addf("%s: snmp: unknown interface %q", p, name)
		}
	}
	for _, a := range s.Allow {
		if _, err := netip.ParsePrefix(a); err != nil {
			v.addf("%s: snmp: invalid allow prefix %q", p, a)
		}
	}
}
