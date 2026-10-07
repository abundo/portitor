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

// VRFs (Routing → VRF) belong to an instance. Interfaces are put in one by
// name (interfaces.vrf), which a rename rewrites; routes by id. A VRF in use
// can't be deleted. Its name is that of its Linux device, so it may not be
// an interface's, a link end's or an interface zone's of the instance.

func vrfExists(tx *gorm.DB, instanceID uint, name string) bool {
	var n int64
	tx.Model(&models.Vrf{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	return n > 0
}

func prepareVrf(tx *gorm.DB, v, old *models.Vrf) error {
	if err := instanceExists(tx, v.InstanceID); err != nil {
		return err
	}
	if old != nil && old.InstanceID != v.InstanceID {
		return bad("a VRF cannot move to another virtual firewall")
	}
	v.Name = strings.TrimSpace(v.Name)
	if !fwconfig.ValidIfname(v.Name) || v.Name == "lo" {
		return bad("name: a Linux interface name (at most 15 characters, no spaces)")
	}
	if strings.HasPrefix(v.Name, fwconfig.IFBPrefix) || strings.HasPrefix(v.Name, fwconfig.NAT64DevicePrefix) ||
		strings.HasPrefix(v.Name, "vrrp4-") || strings.HasPrefix(v.Name, "vrrp6-") {
		return bad("name: that prefix is for the firewall's own devices")
	}
	v.Description = strings.TrimSpace(v.Description)
	if !fwconfig.ValidName(v.Description) && v.Description != "" {
		return bad("description: no control characters")
	}
	if msg := fwconfig.CheckVRFTable(v.RouteTable); msg != "" {
		return bad("table: " + msg)
	}
	names, err := ifaceNames(tx, v.InstanceID)
	if err != nil {
		return err
	}
	if names[v.Name] {
		return bad(fmt.Sprintf("name: %s is an interface of this virtual firewall", v.Name))
	}
	if ifaceZoneExists(tx, v.InstanceID, v.Name) {
		return bad(fmt.Sprintf("name: an interface zone is named %s", v.Name))
	}
	var others []models.Vrf
	if err := tx.Where("instance_id = ? AND id <> ?", v.InstanceID, v.ID).Find(&others).Error; err != nil {
		return err
	}
	for _, o := range others {
		if o.Name == v.Name {
			return bad(fmt.Sprintf("name: there is a VRF %s already", v.Name))
		}
		if o.RouteTable == v.RouteTable {
			return bad(fmt.Sprintf("table: %d is VRF %s's", v.RouteTable, o.Name))
		}
	}
	if old != nil && old.Name != v.Name {
		return tx.Model(&models.Interface{}).Where("instance_id = ? AND vrf = ?", v.InstanceID, old.Name).UpdateColumn("vrf", v.Name).Error
	}
	return nil
}

func deleteVrf(tx *gorm.DB, v *models.Vrf) error {
	var users []string
	var ifs, routes []string
	tx.Model(&models.Interface{}).Where("instance_id = ? AND vrf = ?", v.InstanceID, v.Name).Order("name").Pluck("name", &ifs)
	tx.Model(&models.Route{}).Where("vrf_id = ?", v.ID).Order("destination").Pluck("destination", &routes)
	for _, i := range ifs {
		users = append(users, "interface "+i)
	}
	for _, r := range routes {
		users = append(users, "route "+r)
	}
	if len(users) == 0 {
		return nil
	}
	if len(users) > 5 {
		users = append(users[:5], "...")
	}
	return bad(fmt.Sprintf("VRF %s is used by %s", v.Name, strings.Join(users, ", ")))
}

// prepareIfaceVrf checks an interface's VRF: one of its virtual firewall's
// (so an interface moving to another one leaves it first), and not for a
// bridge's member, which the bridge takes along.
func prepareIfaceVrf(tx *gorm.DB, i *models.Interface) error {
	i.Vrf = strings.TrimSpace(i.Vrf)
	if i.Vrf == "" {
		return nil
	}
	if !vrfExists(tx, i.InstanceID, i.Vrf) {
		return bad(fmt.Sprintf("VRF: %s is not a VRF of this virtual firewall", i.Vrf))
	}
	var bridges []models.Interface
	if err := tx.Where("instance_id = ? AND kind = ? AND id <> ?", i.InstanceID, fwconfig.KindBridge, i.ID).Find(&bridges).Error; err != nil {
		return err
	}
	for _, b := range bridges {
		for _, m := range b.Members {
			if m == i.Name {
				return bad(fmt.Sprintf("VRF: %s is a member of bridge %s; put the bridge in the VRF", i.Name, b.Name))
			}
		}
	}
	return nil
}
