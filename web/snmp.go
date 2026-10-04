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

// SNMP, per instance: the instance's snmp_* fields (prepareInstanceSNMP),
// its interfaces' snmp_serve, and its SNMPv3 users. The community and the
// users' passwords are write-only.

func prepareInstanceSNMP(tx *gorm.DB, in *models.Instance) error {
	switch {
	case in.ClearSnmpCommunity:
		in.SnmpCommunity = ""
	case in.NewSnmpCommunity != "":
		in.SnmpCommunity = in.NewSnmpCommunity
	}
	in.NewSnmpCommunity, in.ClearSnmpCommunity = "", false
	if in.SnmpCommunity != "" {
		if e := fwconfig.CheckSNMPCommunity(in.SnmpCommunity); e != "" {
			return bad("SNMP: " + e)
		}
	}
	in.SnmpLocation, in.SnmpContact = strings.TrimSpace(in.SnmpLocation), strings.TrimSpace(in.SnmpContact)
	if !fwconfig.CheckSNMPText(in.SnmpLocation) || !fwconfig.CheckSNMPText(in.SnmpContact) {
		return bad("SNMP: location and contact must be one line of at most 255 characters")
	}
	in.SnmpAllow = cleanList(in.SnmpAllow)
	if err := checkEntries(tx, "SNMP allowed clients", in.SnmpAllow, entryCIDR); err != nil {
		return err
	}
	if in.SnmpEnabled && in.SnmpCommunity == "" {
		var n int64
		if in.ID != 0 {
			if err := tx.Model(&models.SnmpUser{}).Where("instance_id = ? AND enabled", in.ID).Count(&n).Error; err != nil {
				return err
			}
		}
		if n == 0 {
			return bad("SNMP: set a community (SNMPv2c) or add an SNMPv3 user first")
		}
	}
	return nil
}

func presentInstance(in *models.Instance) {
	in.HasSnmpCommunity = in.SnmpCommunity != ""
	in.NewSnmpCommunity, in.ClearSnmpCommunity = "", false
}

func prepareSnmpUser(tx *gorm.DB, u, old *models.SnmpUser) error {
	if old != nil {
		u.InstanceID = old.InstanceID
	}
	if err := instanceExists(tx, u.InstanceID); err != nil {
		return err
	}
	u.Name = strings.TrimSpace(u.Name)
	if u.NewAuthPassword != "" {
		u.AuthPassword = u.NewAuthPassword
	}
	if u.NewPrivPassword != "" {
		u.PrivPassword = u.NewPrivPassword
	}
	u.NewAuthPassword, u.NewPrivPassword = "", ""
	if u.PrivProtocol == "" {
		u.PrivPassword = ""
	}
	if errs := fwconfig.CheckSNMPUser(u.User()); len(errs) > 0 {
		return bad(fmt.Sprintf("SNMPv3 user %s: %s", u.Name, strings.Join(errs, "; ")))
	}
	if u.AuthPassword == u.PrivPassword {
		return bad("SNMPv3 user " + u.Name + ": use a different privacy password than the authentication one")
	}
	var n int64
	if err := tx.Model(&models.SnmpUser{}).Where("instance_id = ? AND name = ? AND id <> ?", u.InstanceID, u.Name, u.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("there is already an SNMPv3 user %s", u.Name))
	}
	return nil
}

func presentSnmpUser(u *models.SnmpUser) {
	u.HasAuthPassword, u.HasPrivPassword = u.AuthPassword != "", u.PrivPassword != ""
	u.NewAuthPassword, u.NewPrivPassword = "", ""
}
