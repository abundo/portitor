// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// DynDNSServerAddr returns a DynDNS server as ip:port, port 53 by default.
func DynDNSServerAddr(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil && ap.Addr().Zone() == "" {
		return ap, nil
	}
	a, err := ParseAddr(strings.Trim(s, "[]"))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an IP address with an optional port", s)
	}
	return netip.AddrPortFrom(a, 53), nil
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
		dp := fmt.Sprintf("%s: dynamic dns %q", p, d.Name)
		if !zoneNameRe.MatchString(d.Name) {
			v.addf("%s: name must match %s", dp, zoneNameRe)
		}
		if names[d.Name] {
			v.addf("%s: duplicate", dp)
		}
		names[d.Name] = true
		if ifaces[d.Interface] == nil {
			v.addf("%s: unknown interface %q", dp, d.Interface)
		}
		if _, err := DynDNSServerAddr(d.Server); err != nil {
			v.addf("%s: server: %v", dp, err)
		}
		if !validDomain(d.Zone) {
			v.addf("%s: invalid zone %q", dp, d.Zone)
		}
		if t := d.TSIG; t != nil {
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
