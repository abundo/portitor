// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"encoding/pem"
	"slices"
	"strings"
)

// Directory is the firewall's directory of users as the agent needs it:
// the LDAP and Active Directory servers that check the passwords of the
// users portitor-config doesn't have, or has as directory users, tried in
// order (portitor-config's Admin → Directory). The agent asks them for
// OpenVPN's logins, from its own namespace.
type Directory struct {
	Servers []LDAPServer `json:"servers"`
}

// LDAPServer is one directory server (internal/ldapauth.Config).
type LDAPServer struct {
	Name string `json:"name"`
	// ServerType is "generic" (OpenLDAP and the like) or "ad".
	ServerType string `json:"server_type"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	// TLSMode is "none", "starttls" or "ldaps".
	TLSMode       string `json:"tls_mode"`
	SkipTLSVerify bool   `json:"skip_tls_verify,omitempty"`
	// CACert (PEM) verifies the server's certificate; empty: the system's.
	CACert       string `json:"ca_cert,omitempty"`
	BindDN       string `json:"bind_dn,omitempty"`
	BindPassword string `json:"bind_password,omitempty"`
	BaseDN       string `json:"base_dn"`
	// UserFilter finds the user, %s the escaped name.
	UserFilter string `json:"user_filter"`
	AttrGroups string `json:"attr_groups,omitempty"`
}

// LDAP server types and TLS modes (internal/ldapauth's).
var (
	LDAPServerTypes = []string{"generic", "ad"}
	LDAPTLSModes    = []string{"none", "starttls", "ldaps"}
)

// checkLDAPText: one line, at most 1024 characters.
func checkLDAPText(s string) bool {
	return len(s) <= 1024 && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// CheckLDAPServer checks a directory server; it returns its problems.
func CheckLDAPServer(l LDAPServer) []string {
	var out []string
	if !ValidName(l.Name) || len(l.Name) > 64 {
		out = append(out, "invalid name")
	}
	if !slices.Contains(LDAPServerTypes, l.ServerType) {
		out = append(out, "type must be generic or ad")
	}
	if !slices.Contains(LDAPTLSModes, l.TLSMode) {
		out = append(out, "TLS must be none, starttls or ldaps")
	}
	if !validHost(l.Host) {
		out = append(out, "host must be a name or an address")
	}
	if l.Port < 1 || l.Port > 65535 {
		out = append(out, "port must be 1-65535")
	}
	if l.CACert != "" {
		if b, _ := pem.Decode([]byte(l.CACert)); b == nil || b.Type != "CERTIFICATE" {
			out = append(out, "CA certificate must be PEM")
		}
	}
	for _, f := range []struct{ what, v string }{{"bind DN", l.BindDN}, {"bind password", l.BindPassword}, {"base DN", l.BaseDN},
		{"user filter", l.UserFilter}, {"groups attribute", l.AttrGroups}} {
		if !checkLDAPText(f.v) {
			out = append(out, f.what+" must be one line of at most 1024 characters")
		}
	}
	if l.BaseDN == "" {
		out = append(out, "base DN is required")
	}
	if !strings.HasPrefix(l.UserFilter, "(") || !strings.HasSuffix(l.UserFilter, ")") || strings.Count(l.UserFilter, "%s") != 1 || strings.Count(l.UserFilter, "%") != 1 {
		out = append(out, "the user filter must be in parentheses and hold %s once")
	}
	if l.BindPassword != "" && l.BindDN == "" {
		out = append(out, "bind password without a bind DN")
	}
	return out
}

func (v *validator) directory(d *Directory) {
	names := map[string]bool{}
	for _, l := range d.Servers {
		for _, e := range CheckLDAPServer(l) {
			v.addf("directory server %q: %s", l.Name, e)
		}
		if names[l.Name] {
			v.addf("directory server %q: duplicate", l.Name)
		}
		names[l.Name] = true
	}
}

// validHost: a DNS name or an address, for a server to dial.
func validHost(s string) bool {
	if _, err := ParseAddr(s); err == nil {
		return true
	}
	return validDomain(s) && !strings.HasSuffix(s, ".") || s == "localhost"
}
