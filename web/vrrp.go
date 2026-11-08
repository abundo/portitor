// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// VRRP virtual routers, per instance, on an interface by name (renaming
// one rewrites them, deleting one in use is refused, web/ifzones.go).

// vrrpIfaceUsers lists the virtual routers on interface name.
func vrrpIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var ids []int
	tx.Model(&models.VrrpRouter{}).Where("instance_id = ? AND interface = ?", instanceID, name).Order("vrid").Pluck("vrid", &ids)
	var users []string
	for _, id := range ids {
		users = append(users, fmt.Sprintf("VRRP %d", id))
	}
	return users
}
