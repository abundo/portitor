// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// DynDNSServer returns a DynDNS server as host:port, port 53 by default.
// The host is an IP address or a DNS name with at least one dot (the
// agent resolves it in the instance): 192.0.2.53, [2001:db8::53]:5353,
// ns1.example.com, ns1.example.com:5353.
func DynDNSServer(s string) (string, error) {
	bad := fmt.Errorf("%q is not an IP address or DNS name with an optional port", s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Addr().Zone() != "" || ap.Port() == 0 {
			return "", bad
		}
		return ap.String(), nil
	}
	if a, err := ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(a, 53).String(), nil
	}
	host, port := s, "53"
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", bad
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !validDomain(host) || !strings.Contains(host, ".") {
		return "", bad
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", bad // an IPv6 address with a port needs brackets
	}
	return net.JoinHostPort(host, port), nil
}

// DynDNSOwner resolves a record name against zone (both may lack the
// trailing dot) to a lower-case FQDN with a trailing dot:
//
//   - "@" is the zone apex
//   - absolute names (trailing ".") must lie in the zone
//   - names that already end with the zone are FQDNs in the zone
//   - other names are relative and get the zone appended
func DynDNSOwner(name, zone string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	zone = strings.ToLower(strings.TrimSuffix(zone, ".")) + "."
	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if name == "@" {
		return zone, nil
	}
	absolute := strings.HasSuffix(name, ".")
	candidate := name
	if !absolute {
		candidate += "."
	}
	if candidate == zone || strings.HasSuffix(candidate, "."+zone) {
		return candidate, nil
	}
	if absolute {
		return "", fmt.Errorf("%q is not in zone %q", name, zone)
	}
	return name + "." + zone, nil
}

func (v *validator) dyndns(p string, in *Instance, ifaces map[string]*Interface) {
	names := map[string]bool{}
	for _, d := range in.DynDNS {
		dp := fmt.Sprintf("%s: dns update %q", p, d.Name)
		if !ValidFileName(d.Name) {
			v.addf("%s: invalid name", dp)
		}
		if names[d.Name] {
			v.addf("%s: duplicate", dp)
		}
		names[d.Name] = true
		if ifaces[d.Interface] == nil {
			v.addf("%s: unknown interface %q", dp, d.Interface)
		}
		v.dnsProvider(dp, d)
		if !validDomain(d.Zone) {
			v.addf("%s: invalid zone %q", dp, d.Zone)
		}
		if t := d.TSIG; t != nil && (d.Provider == "" || d.Provider == ProviderRFC2136) {
			if !validDomain(t.Name) {
				v.addf("%s: invalid TSIG key name %q", dp, t.Name)
			}
			if !slices.Contains(TSIGAlgorithms, t.Algorithm) {
				v.addf("%s: TSIG algorithm must be one of %s", dp, strings.Join(TSIGAlgorithms, ", "))
			}
			if b, err := base64.StdEncoding.DecodeString(t.Secret); err != nil || len(b) == 0 {
				v.addf("%s: TSIG secret must be base64", dp)
			}
		}
		for field, n := range map[string]int{"retry interval": d.RetryInterval, "verify interval": d.VerifyInterval} {
			if n != 0 && (n < 10 || n > 7*86400) {
				v.addf("%s: %s must be 10-604800 seconds (0 for the default)", dp, field)
			}
		}
		if len(d.Records) == 0 {
			v.addf("%s: needs at least one record", dp)
		}
		types := map[string][]string{} // owner -> types
		for _, r := range d.Records {
			v.dyndnsRecord(dp, d.Zone, r, types)
		}
		for owner, ts := range types {
			if slices.Contains(ts, "CNAME") && len(ts) > 1 {
				v.addf("%s: %s has a CNAME and other records", dp, owner)
			}
		}
	}
}

// dnsProvider checks a client's provider and its settings: RFC 2136 needs
// a server, the others their required fields and no server or TSIG key.
func (v *validator) dnsProvider(dp string, d DynDNS) {
	p := FindDNSProvider(d.Provider)
	if p == nil {
		v.addf("%s: unknown provider %q", dp, d.Provider)
		return
	}
	if p.Name == ProviderRFC2136 {
		if _, err := DynDNSServer(d.Server); err != nil {
			v.addf("%s: server: %v", dp, err)
		}
	} else if d.Server != "" || d.TSIG != nil {
		v.addf("%s: a server and TSIG key are for RFC 2136 only", dp)
	}
	for key, val := range d.ProviderSettings {
		f := p.Field(key)
		if f == nil {
			v.addf("%s: %s has no setting %q", dp, p.Label, key)
			continue
		}
		if len(val) > 4096 || strings.ContainsFunc(val, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
			v.addf("%s: %s: control characters or too long", dp, f.Label)
		}
	}
	for _, f := range p.Fields {
		if f.Required && d.ProviderSettings[f.Key] == "" {
			v.addf("%s: %s needs %s", dp, p.Label, f.Label)
		}
	}
}

func (v *validator) dyndnsRecord(dp, zone string, r DynDNSRecord, types map[string][]string) {
	rp := fmt.Sprintf("%s: record %s %s", dp, r.Name, r.Type)
	owner, err := DynDNSOwner(r.Name, zone)
	if err != nil {
		v.addf("%s: %v", rp, err)
		return
	}
	for _, label := range strings.Split(strings.TrimSuffix(owner, "."), ".") {
		if label == "@" || !dnsLabelRe.MatchString(label) {
			v.addf("%s: invalid name", rp)
			return
		}
	}
	if slices.Contains(types[owner], r.Type) {
		// An update replaces the whole RRset, so two would fight.
		v.addf("%s: duplicate (one record per name and type)", rp)
	}
	types[owner] = append(types[owner], r.Type)
	if r.TTL < 0 || r.TTL > 2147483647 {
		v.addf("%s: invalid ttl %d", rp, r.TTL)
	}
	switch r.Type {
	case "A", "AAAA":
		if r.Value == "" {
			break
		}
		if a, err := netip.ParseAddr(r.Value); err != nil || a.Is4() != (r.Type == "A") || a.Zone() != "" {
			v.addf("%s: invalid IPv%s address %q", rp, map[bool]string{true: "4", false: "6"}[r.Type == "A"], r.Value)
		}
	case "CNAME":
		if r.Value != "@" && !validDomain(r.Value) {
			v.addf("%s: invalid target %q", rp, r.Value)
		}
	case "TXT":
		if len(r.Value) > 255 {
			v.addf("%s: value longer than 255 characters", rp)
		}
		for _, c := range r.Value {
			if c < 0x20 || c == 0x7f {
				v.addf("%s: value contains control characters", rp)
				break
			}
		}
	default:
		v.addf("%s: type must be one of %s", rp, strings.Join(DynDNSRecordTypes, ", "))
	}
}
