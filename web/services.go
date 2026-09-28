// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// Custom services. Rules refer to them by name next to the predefined ones
// (netobj.Predefined); renaming one rewrites those lists, and one in use
// cannot be deleted.

func prepareService(tx *gorm.DB, s, old *models.Service) error {
	s.Name = strings.ToLower(strings.TrimSpace(s.Name))
	if !netobj.ValidServiceName(s.Name) {
		if slices.ContainsFunc(netobj.Predefined, func(p models.Service) bool { return p.Name == s.Name }) {
			return bad(fmt.Sprintf("name: %s is a predefined service", s.Name))
		}
		return bad("name: lower-case letters, digits, _ . -, starting with a letter, at most 63 characters")
	}
	s.Description = strings.TrimSpace(s.Description)
	// Only the fields of the service's type are kept.
	if s.Type != models.ServiceTypePorts {
		s.Ports = models.ServicePortList{}
	}
	if s.Type != models.ServiceTypeICMP && s.Type != models.ServiceTypeICMP6 {
		s.IcmpType, s.IcmpCode = "", nil
	}
	if s.Type != models.ServiceTypeIP {
		s.IpProtocol = 0
	}
	if s.Ports == nil {
		s.Ports = models.ServicePortList{}
	}
	for i := range s.Ports {
		if p := &s.Ports[i]; p.DstHi == p.DstLo {
			p.DstHi = 0
		}
		if p := &s.Ports[i]; p.SrcHi == p.SrcLo {
			p.SrcHi = 0
		}
	}
	if err := netobj.CheckService(*s); err != nil {
		return bad(err.Error())
	}
	if old != nil && old.Name != s.Name {
		return eachServiceRef(tx, func(_ string, entry *string) bool {
			if *entry == old.Name {
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
	err := eachServiceRef(tx, func(where string, entry *string) bool {
		if *entry == s.Name && (len(users) == 0 || users[len(users)-1] != where) {
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

// eachServiceRef calls visit for every entry of the rules' service lists.
// Rules where visit changed an entry are saved.
func eachServiceRef(tx *gorm.DB, visit func(where string, entry *string) bool) error {
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
		where := fmt.Sprintf("%s in %s", names.rule(r), instName[r.InstanceID])
		changed := false
		for i := range r.Services {
			if visit(where, &r.Services[i]) {
				changed = true
			}
		}
		if changed {
			if err := tx.Model(&models.Rule{}).Where("id = ?", r.ID).UpdateColumn("services", r.Services).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// checkServices checks that a rule's service names are custom or
// predefined services. The builder expands them at deploy time.
func checkServices(tx *gorm.DB, names models.StringList) error {
	if len(names) == 0 {
		return nil
	}
	var list []models.Service
	if err := tx.Find(&list).Error; err != nil {
		return err
	}
	if _, err := netobj.NewServices(list).Expand(names); err != nil {
		return bad("services: " + err.Error())
	}
	return nil
}
