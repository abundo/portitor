// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Rate limits belong to an instance; its rules name them. Renaming one
// rewrites the rules, deleting one in use is refused, and a rate limit
// never moves to another instance.

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
