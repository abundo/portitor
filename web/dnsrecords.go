// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// checkRecord normalises a record and validates it as it will be built:
// under domain (the $DOMAIN row above it, or "").
func checkRecord(z *models.DnsZone, r *models.DnsRecord, domain string) error {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Description = strings.TrimSpace(r.Description)
	if strings.ContainsFunc(r.Description, isControl) {
		return bad("description contains control characters")
	}
	switch r.Type {
	case models.DnsRecordComment:
		r.Name, r.Ttl, r.Mac, r.Description = ";", 0, "", ""
		r.Value = strings.TrimSpace(r.Value)
		if strings.ContainsFunc(r.Value, isControl) {
			return bad("comment contains control characters")
		}
		return nil
	case models.DnsRecordDomain:
		// Relative to the zone; the absolute form is accepted too.
		name := strings.ToLower(strings.TrimSpace(r.Name))
		if abs, ok := strings.CutSuffix(name, "."+z.Name+"."); ok {
			name = abs
		}
		r.Name, r.Ttl, r.Value, r.Mac, r.Description = name, 0, "", "", ""
		if !fwconfig.ValidDomain(name) || strings.HasSuffix(name, ".") {
			return bad("$DOMAIN needs a subdomain name relative to the zone, e.g. lab")
		}
		return nil
	}
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		r.Name = "@"
	}
	r.Value = strings.TrimSpace(r.Value)
	if r.Ttl < 0 {
		r.Ttl = 0
	}
	r.Mac = normalizeMAC(r.Mac)
	return checkDNS(fwconfig.DNSServer{Zones: []fwconfig.DNSZone{{Name: z.Name, Type: z.Type, Records: []fwconfig.DNSRecord{
		{Name: builder.RecordName(domain, r.Name), TTL: r.Ttl, Type: r.Type, Value: r.Value, MAC: r.Mac},
	}}}})
}

// normalizeMAC turns aa-bb-.., aabb.ccdd.eeff and aabbccddeeff into
// aa:bb:cc:dd:ee:ff. Anything else is returned trimmed, for validation to
// reject.
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
