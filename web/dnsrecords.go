// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// handleZoneRecords is PUT /api/dns/zones/:id/records: the zone editor
// saves the whole grid, in order, replacing the zone's records.
func (s *Server) handleZoneRecords(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var body []models.DnsRecord
	if err := json.NewDecoder(c.Request().Body).Decode(&body); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	var z models.DnsZone
	if err := s.db.First(&z, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errJSON(c, http.StatusNotFound, "not found")
		}
		return err
	}
	if z.Type != fwconfig.ZoneForward && len(body) > 0 {
		return errJSON(c, http.StatusBadRequest, "records go in forward zones; reverse zones are generated")
	}
	domain := ""
	for i := range body {
		r := &body[i]
		r.ID, r.ZoneID, r.Rank = 0, z.ID, i
		if err := checkRecord(&z, r, domain); err != nil {
			return errJSON(c, http.StatusBadRequest, fmt.Sprintf("record %d: %v", i+1, err))
		}
		if r.Type == models.DnsRecordDomain {
			domain = r.Name
		}
	}
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("zone_id = ?", z.ID).Delete(&models.DnsRecord{}).Error; err != nil {
			return err
		}
		if len(body) == 0 {
			return nil
		}
		return tx.Create(&body).Error
	})
	if err != nil {
		return dbError(c, err)
	}
	out := []models.DnsRecord{}
	if err := s.db.Where("zone_id = ?", z.ID).Order("rank, id").Find(&out).Error; err != nil {
		return err
	}
	return c.JSON(http.StatusOK, out)
}

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
