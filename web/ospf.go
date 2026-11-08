// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"slices"

	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// OSPF, per instance and version (2: OSPFv2, IPv4; 3: OSPFv3, IPv6): the
// configuration, and the interfaces it runs on. Interfaces are referred to
// by name (renaming one rewrites them, deleting one in use is refused,
// web/ifzones.go), route maps as BGP does (eachRoutingRef).

func presentOspfInterface(i *models.OspfInterface) {
	i.HasAuthKey = i.AuthKey != ""
	i.NewAuthKey, i.ClearAuthKey = "", false
}

// ospfIfaceUsers lists the OSPF interfaces named name.
func ospfIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var versions []int
	tx.Model(&models.OspfInterface{}).Where("instance_id = ? AND name = ?", instanceID, name).Order("version").Pluck("version", &versions)
	var users []string
	for _, v := range slices.Compact(versions) {
		users = append(users, fmt.Sprintf("OSPFv%d", v))
	}
	return users
}
