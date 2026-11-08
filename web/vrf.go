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
// an interface's, a link end's or an interface zone's of the instance. Its
// L3VNI (evpn_*, fwconfig.VRFEVPN) names its underlay interface, which a
// rename rewrites (renameIfaceRefs) and which can't be deleted.

func vrfExists(tx *gorm.DB, instanceID uint, name string) bool {
	var n int64
	tx.Model(&models.Vrf{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	return n > 0
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

// Routing rows (BGP, OSPF and IS-IS configs, BGP peer groups and
// neighbours) belong to the main table (vrf_id NULL) or a VRF of their
// instance, and stay there. OSPF and IS-IS interfaces belong to the
// routing of their interface's VRF.
