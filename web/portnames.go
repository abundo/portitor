// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"regexp"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Custom port names. NAT port fields take them next to the built-in ones
// (fwconfig.Services); the builder writes their numbers, so the agent never
// sees them. Renaming one rewrites the NAT rules, and one in use cannot be
// deleted.

var portNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

func preparePortName(tx *gorm.DB, p, old *models.PortName) error {
	p.Name = strings.ToLower(strings.TrimSpace(p.Name))
	if !portNameRe.MatchString(p.Name) {
		return bad("name: lower-case letters, digits, _ . -, starting with a letter, at most 63 characters")
	}
	if _, ok := fwconfig.ServicePort(p.Name); ok {
		return bad(fmt.Sprintf("name: %s is a built-in port name", p.Name))
	}
	if p.Port < 1 || p.Port > 65535 {
		return bad("port: 1 to 65535")
	}
	p.Description = strings.TrimSpace(p.Description)
	if old != nil && old.Name != p.Name {
		return eachPortNameRef(tx, func(_ string, entry *string) bool {
			if *entry == old.Name {
				*entry = p.Name
				return true
			}
			return false
		})
	}
	return nil
}

func deletePortName(tx *gorm.DB, p *models.PortName) error {
	var users []string
	err := eachPortNameRef(tx, func(where string, entry *string) bool {
		if *entry == p.Name && (len(users) == 0 || users[len(users)-1] != where) {
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
		return bad(fmt.Sprintf("%s is used by %s", p.Name, strings.Join(users, ", ")))
	}
	return nil
}

// portNames returns the custom port names and their ports.
func portNames(tx *gorm.DB) (map[string]int, error) {
	var list []models.PortName
	if err := tx.Find(&list).Error; err != nil {
		return nil, err
	}
	m := make(map[string]int, len(list))
	for _, p := range list {
		m[p.Name] = p.Port
	}
	return m, nil
}

// eachPortNameRef calls visit for every entry of the NAT rules' port lists
// (lower-cased, as names match). Rules where visit changed an entry are saved.
func eachPortNameRef(tx *gorm.DB, visit func(where string, entry *string) bool) error {
	instName := map[uint]string{}
	var instances []models.Instance
	if err := tx.Find(&instances).Error; err != nil {
		return err
	}
	for _, in := range instances {
		instName[in.ID] = in.Name
	}
	var rules []models.NatRule
	if err := tx.Where("dst_ports <> ''").Order("instance_id, position, id").Find(&rules).Error; err != nil {
		return err
	}
	for _, n := range rules {
		where := fmt.Sprintf("NAT rule %q of %s", n.Description, instName[n.InstanceID])
		if n.Description == "" {
			where = fmt.Sprintf("NAT rule %d of %s", n.ID, instName[n.InstanceID])
		}
		parts := strings.Split(n.DstPorts, ",")
		changed := false
		for i := range parts {
			entry := strings.ToLower(strings.TrimSpace(parts[i]))
			if visit(where, &entry) {
				parts[i], changed = entry, true
			}
		}
		if changed {
			if err := tx.Model(&models.NatRule{}).Where("id = ?", n.ID).UpdateColumn("dst_ports", strings.Join(parts, ",")).Error; err != nil {
				return err
			}
		}
	}
	return nil
}
