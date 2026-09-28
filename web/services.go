// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// Custom services. Rule and NAT port lists refer to them by name next to
// the built-in names; renaming one rewrites those lists, and one in use
// cannot be deleted.

func prepareService(tx *gorm.DB, s, old *models.Service) error {
	s.Name = strings.ToLower(strings.TrimSpace(s.Name))
	if !netobj.ValidServiceName(s.Name) {
		if _, builtin := fwconfig.ServicePort(s.Name); builtin {
			return bad(fmt.Sprintf("name: %s is a built-in service", s.Name))
		}
		return bad("name: lower-case letters, digits, _ . -, starting with a letter, at most 63 characters")
	}
	// Ports: numbers, ranges and built-in names; a custom name would make
	// expansion depend on the order of the services.
	parts := strings.Split(s.Ports, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	s.Ports = strings.Join(parts, ", ")
	if _, err := fwconfig.ParsePorts(s.Ports); err != nil {
		return bad("ports: " + err.Error() + "; use ports (80, 443), a range (8000-8080) or built-in service names")
	}
	if old != nil && old.Name != s.Name {
		return eachPortRef(tx, func(_ string, entry *string) bool {
			if strings.ToLower(*entry) == old.Name {
				*entry = s.Name
				return true
			}
			return false
		})
	}
	return nil
}

func deleteService(tx *gorm.DB, s *models.Service) error {
	var users []string
	err := eachPortRef(tx, func(where string, entry *string) bool {
		if strings.ToLower(*entry) == s.Name && (len(users) == 0 || users[len(users)-1] != where) {
			users = append(users, where)
		}
		return false
	})
	if err != nil {
		return err
	}
	if len(users) > 0 {
		if len(users) > 5 {
			users = append(users[:5], "...")
		}
		return bad(fmt.Sprintf("%s is used by %s", s.Name, strings.Join(users, ", ")))
	}
	return nil
}

// eachPortRef calls visit for every entry of the rule and NAT port lists.
// Rows where visit changed an entry are saved, their lists joined by ", ".
func eachPortRef(tx *gorm.DB, visit func(where string, entry *string) bool) error {
	ports := func(where string, s *string) bool {
		if *s == "" {
			return false
		}
		parts := strings.Split(*s, ",")
		changed := false
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
			if visit(where, &parts[i]) {
				changed = true
			}
		}
		if changed {
			*s = strings.Join(parts, ", ")
		}
		return changed
	}
	instName := map[uint]string{}
	var instances []models.Instance
	if err := tx.Find(&instances).Error; err != nil {
		return err
	}
	for _, in := range instances {
		instName[in.ID] = in.Name
	}
	names := ruleNamer{}
	var rules []models.Rule
	if err := tx.Order("position, id").Find(&rules).Error; err != nil {
		return err
	}
	for _, r := range rules {
		if ports(fmt.Sprintf("%s in %s", names.rule(r), instName[r.InstanceID]), &r.DstPorts) {
			if err := tx.Model(&models.Rule{}).Where("id = ?", r.ID).UpdateColumn("dst_ports", r.DstPorts).Error; err != nil {
				return err
			}
		}
	}
	var nat []models.NatRule
	if err := tx.Order("position, id").Find(&nat).Error; err != nil {
		return err
	}
	for _, n := range nat {
		if ports(fmt.Sprintf("%s in %s", names.nat(n), instName[n.InstanceID]), &n.DstPorts) {
			if err := tx.Model(&models.NatRule{}).Where("id = ?", n.ID).UpdateColumn("dst_ports", n.DstPorts).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// checkPorts checks a rule or NAT port list, where custom service names may
// stand in next to numbers, ranges and built-in names. The builder expands
// them at deploy time.
func checkPorts(tx *gorm.DB, ports string) error {
	var list []models.Service
	if err := tx.Find(&list).Error; err != nil {
		return err
	}
	if _, err := netobj.NewServices(list).ExpandPorts(ports); err != nil {
		return bad(err.Error() + "; use ports (22), ranges (8000-8080) or service names (https)")
	}
	return nil
}
