// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Rate limits belong to an instance; its rules name them. Renaming one
// rewrites the rules, deleting one in use is refused, and a rate limit
// never moves to another instance.

func prepareRateLimit(tx *gorm.DB, l, old *models.RateLimit) error {
	if err := instanceExists(tx, l.InstanceID); err != nil {
		return err
	}
	if old != nil && old.InstanceID != l.InstanceID {
		return bad("a rate limit cannot move to another virtual firewall")
	}
	l.Service = ""
	if old != nil {
		l.Service = old.Service
	}
	l.Name, l.Description = strings.TrimSpace(l.Name), strings.TrimSpace(l.Description)
	if !fwconfig.ValidName(l.Name) {
		return bad("name: no control characters")
	}
	if l.Rate < 1 || l.Rate > fwconfig.MaxRate {
		return bad(fmt.Sprintf("rate: 1-%d", fwconfig.MaxRate))
	}
	if l.Burst < 0 || l.Burst > fwconfig.MaxRate {
		return bad(fmt.Sprintf("burst: 0-%d", fwconfig.MaxRate))
	}
	// Rates are per second: policing packets per second or Mbit/s,
	// shaping Mbit/s or kbit/s.
	l.Per = fwconfig.RatePerSecond
	if l.Shape {
		l.Burst, l.PerSource, l.Connections = 0, false, false
		if l.Unit == "" {
			l.Unit = fwconfig.RateUnitMBit
		}
		if l.Unit != fwconfig.RateUnitMBit && l.Unit != fwconfig.RateUnitKBit {
			return bad("unit: shaping is in mbit or kbit per second")
		}
		var n int64
		err := tx.Model(&models.RateLimit{}).Where("instance_id = ? AND shape AND id <> ?", l.InstanceID, l.ID).Count(&n).Error
		if err != nil {
			return err
		}
		if n >= fwconfig.MaxShapers {
			return bad(fmt.Sprintf("at most %d rate limits that shape in a virtual firewall", fwconfig.MaxShapers))
		}
	} else {
		if l.Unit != "" && l.Unit != fwconfig.RateUnitMBit {
			return bad("unit: policing is in packets or mbit per second")
		}
		if l.Unit != "" && !l.Connections {
			return bad("unit: policing Mbit/s needs Whole connections")
		}
	}
	if l.Connections || l.Shape {
		if err := checkConnectionRules(tx, l.InstanceID, oldName(old)); err != nil {
			return err
		}
	}
	if l.Shape && l.Service != "" {
		return bad("this is a service's rate limit, which polices; it can't shape")
	}
	if old != nil && old.Name != l.Name {
		return tx.Model(&models.Rule{}).Where("instance_id = ? AND rate_limit = ?", l.InstanceID, old.Name).
			UpdateColumn("rate_limit", l.Name).Error
	}
	return nil
}

func deleteRateLimit(tx *gorm.DB, l *models.RateLimit) error {
	if l.Service != "" {
		var in models.Instance
		if err := tx.First(&in, l.InstanceID).Error; err != nil {
			return err
		}
		for _, sv := range serviceRateLimits {
			if sv.service == l.Service && *sv.on(&in) {
				return bad(fmt.Sprintf("%s is the %s's rate limit; switch it off on the %s page first", l.Name, sv.label, sv.page))
			}
		}
	}
	return refuseRuleRef(tx, l.InstanceID, l.Name, func(r models.Rule) string { return r.RateLimit })
}

// serviceRateLimits are the services open to a subnet
// (fwconfig.ServiceRateLimit): each may police with its rate limit
// (models.RateLimit.Service), switched on by the instance's column, and
// named, at first, name.
var serviceRateLimits = []struct {
	service, column, label, page, name, description string
	on                                              func(*models.Instance) *bool
}{
	{"dns", "dns_rate_limit", "DNS server", "DNS", "dns server", "What comes in to the DNS server", func(in *models.Instance) *bool { return &in.DnsRateLimit }},
	{"dhcp", "dhcp_rate_limit", "DHCP server", "DHCP", "dhcp server", "What comes in to the DHCP server", func(in *models.Instance) *bool { return &in.DhcpRateLimit }},
	{"ntp", "ntp_rate_limit", "NTP server", "NTP", "ntp server", "What comes in to the NTP server", func(in *models.Instance) *bool { return &in.NtpRateLimit }},
}

// prepareServiceRateLimits makes the rate limit of each service an
// instance switches its rate limit on for, unless it has one. A new
// instance gets them all after it is created (createServiceRateLimits).
func prepareServiceRateLimits(tx *gorm.DB, in *models.Instance) error {
	if in.ID == 0 {
		return nil
	}
	for i, sv := range serviceRateLimits {
		if *sv.on(in) {
			if err := ensureServiceRateLimit(tx, in.ID, i); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureServiceRateLimit makes the instance's rate limit of
// serviceRateLimits[i], policing fwconfig.DefaultServiceRate Mbit/s, unless
// it has one; named after the service, or with a number when that name is
// taken.
func ensureServiceRateLimit(tx *gorm.DB, instanceID uint, i int) error {
	sv := serviceRateLimits[i]
	var n int64
	if err := tx.Model(&models.RateLimit{}).Where("instance_id = ? AND service = ?", instanceID, sv.service).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	name := sv.name
	for k := 2; ; k++ {
		if err := tx.Model(&models.RateLimit{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n).Error; err != nil {
			return err
		}
		if n == 0 {
			break
		}
		name = fmt.Sprintf("%s %d", sv.name, k)
	}
	return tx.Create(&models.RateLimit{InstanceID: instanceID, Name: name, Description: sv.description, Service: sv.service,
		Rate: fwconfig.DefaultServiceRate, Unit: fwconfig.RateUnitMBit, Per: fwconfig.RatePerSecond, Connections: true}).Error
}

// createServiceRateLimits gives a new instance the rate limits of its
// services, switched on.
func createServiceRateLimits(tx *gorm.DB, in *models.Instance) error {
	for i, sv := range serviceRateLimits {
		if err := ensureServiceRateLimit(tx, in.ID, i); err != nil {
			return err
		}
		if err := tx.Model(in).UpdateColumn(sv.column, true).Error; err != nil {
			return err
		}
		*sv.on(in) = true
	}
	return nil
}

// refuseRuleRef refuses to delete what the instance's rules name in the
// field ref returns.
func refuseRuleRef(tx *gorm.DB, instanceID uint, name string, ref func(models.Rule) string) error {
	var rules []models.Rule
	if err := tx.Where("instance_id = ?", instanceID).Order("position, id").Find(&rules).Error; err != nil {
		return err
	}
	names := ruleNamer{}
	var users []string
	for _, r := range rules {
		where := names.rule(r)
		if ref(r) == name {
			users = append(users, where)
		}
	}
	if len(users) > 0 {
		if len(users) > 5 {
			users = append(users[:5], "...")
		}
		return bad(fmt.Sprintf("%s is used by %s", name, strings.Join(users, ", ")))
	}
	return nil
}

func oldName(old *models.RateLimit) string {
	if old == nil {
		return ""
	}
	return old.Name
}

// checkConnectionRules refuses a limit that polices connections while a
// rule that is not an accept rule names it: only accepts mark them.
func checkConnectionRules(tx *gorm.DB, instanceID uint, name string) error {
	if name == "" {
		return nil
	}
	var n int64
	err := tx.Model(&models.Rule{}).Where("instance_id = ? AND rate_limit = ? AND action <> ?", instanceID, name, fwconfig.ActionAccept).Count(&n).Error
	if err != nil {
		return err
	}
	if n > 0 {
		return bad("a rule that names this limit is not an accept rule; only accepts limit or shape their connections")
	}
	return nil
}

// checkRateLimit checks that a rule's rate limit is one of its instance's,
// and that one which polices connections is named by an accept rule.
func checkRateLimit(tx *gorm.DB, instanceID uint, name, action string) error {
	if name == "" {
		return nil
	}
	var l models.RateLimit
	err := tx.Where("instance_id = ? AND name = ?", instanceID, name).Limit(1).Find(&l).Error
	if err != nil {
		return err
	}
	if l.ID == 0 {
		return bad(fmt.Sprintf("rate limit: %q is not a rate limit of this virtual firewall", name))
	}
	if (l.Connections || l.Shape) && action != fwconfig.ActionAccept {
		return bad(fmt.Sprintf("rate limit: %s limits or shapes connections, which only an accept rule has", name))
	}
	return nil
}
