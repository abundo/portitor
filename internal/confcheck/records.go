// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confcheck

import (
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
)

// A DNS zone's records, in order: comment rows (type COMMENT, the text in
// value) and $DOMAIN rows (the records below it, to the next, are in that
// subdomain of the zone) between the records, each checked as it will be
// built, under its $DOMAIN.

const (
	recordComment = "COMMENT"
	recordDomain  = "$DOMAIN"
)

func init() {
	register("/instance/dns-zone/record", hook{normalize: normalizeDNSRecord, check: checkDNSRecord})
}

func normalizeDNSRecord(c *Ctx, r *datastore.Node) error {
	trim := func(leaf string) string {
		v := strings.TrimSpace(r.Leaf(leaf))
		if v == "" {
			clear(r, leaf)
		} else {
			set(r, leaf, v)
		}
		return v
	}
	if t := strings.ToUpper(strings.TrimSpace(r.Leaf("type"))); t != "" {
		set(r, "type", t)
	}
	trim("description")
	switch r.Leaf("type") {
	case recordComment:
		set(r, "name", ";")
		clear(r, "ttl", "mac", "description")
		trim("value")
		return nil
	case recordDomain:
		// Relative to the zone; the absolute form is taken too.
		name := strings.ToLower(strings.TrimSpace(r.Leaf("name")))
		if abs, ok := strings.CutSuffix(name, "."+r.Parent.Leaf("name")+"."); ok {
			name = abs
		}
		set(r, "name", name)
		clear(r, "ttl", "value", "mac", "description")
		return nil
	}
	if trim("name") == "" {
		set(r, "name", "@")
	}
	trim("value")
	if ttl, err := strconv.ParseInt(r.Leaf("ttl"), 10, 64); err == nil && ttl <= 0 {
		clear(r, "ttl")
	}
	if m := normalizeMAC(r.Leaf("mac")); m != "" {
		set(r, "mac", m)
	} else {
		clear(r, "mac")
	}
	return nil
}

func checkDNSRecord(c *Ctx, r *datastore.Node) []error {
	if strings.ContainsFunc(r.Leaf("description"), isControl) {
		return []error{fail("description contains control characters")}
	}
	z := r.Parent
	switch r.Leaf("type") {
	case recordComment:
		if strings.ContainsFunc(r.Leaf("value"), isControl) {
			return []error{fail("comment contains control characters")}
		}
		return nil
	case recordDomain:
		if name := r.Leaf("name"); !fwconfig.ValidDomain(name) || strings.HasSuffix(name, ".") {
			return []error{fail("$DOMAIN needs a subdomain name relative to the zone, e.g. lab")}
		}
		return nil
	}
	ttl, _ := strconv.ParseInt(r.Leaf("ttl"), 10, 64)
	rec := fwconfig.DNSRecord{Name: recordName(domainOf(r), r.Leaf("name")), TTL: ttl, Type: r.Leaf("type"), Value: r.Leaf("value"), MAC: r.Leaf("mac")}
	check := fwconfig.Instance{Name: "check", Default: true, DNS: fwconfig.DNSServer{Zones: []fwconfig.DNSZone{
		{Name: z.Leaf("name"), Type: z.Leaf("type"), Records: []fwconfig.DNSRecord{rec}},
	}}}
	err := (&fwconfig.Document{Version: fwconfig.Version, Instances: []fwconfig.Instance{check}}).Validate()
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		return nil
	}
	var errs []error
	for _, p := range ve.Problems {
		errs = append(errs, fail("%s", p[strings.LastIndex(p, ": ")+2:]))
	}
	return errs
}

// domainOf is the $DOMAIN a record is under: the nearest above it in its
// zone, or "".
func domainOf(r *datastore.Node) string {
	recs := r.Parent.Lists["record"]
	at := -1
	for i, x := range recs {
		if x == r {
			at = i
		}
	}
	for i := at - 1; i >= 0; i-- {
		if recs[i].Leaf("type") == recordDomain {
			return recs[i].Leaf("name")
		}
	}
	return ""
}

// recordName is a record's name under domain (builder.RecordName).
func recordName(domain, name string) string {
	switch {
	case domain == "":
		return name
	case name == "" || name == "@":
		return domain
	default:
		return name + "." + domain
	}
}

// normalizeMAC turns aa-bb-.., aabb.ccdd.eeff and aabbccddeeff into
// aa:bb:cc:dd:ee:ff; anything else is returned trimmed, for the check to
// refuse.
func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	hex := strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(hex) != 12 || strings.Trim(hex, "0123456789abcdef") != "" {
		return s
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = hex[2*i : 2*i+2]
	}
	return strings.Join(parts, ":")
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }
