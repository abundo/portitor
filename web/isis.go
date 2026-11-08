// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// IS-IS, per instance: the configuration, and the interfaces it runs on.
// Interfaces are referred to by name (renaming one rewrites them, deleting
// one in use is refused, web/ifzones.go), route maps as BGP does
// (eachRoutingRef).

func presentIsisConfig(c *models.IsisConfig) {
	c.HasAreaPassword, c.HasDomainPassword = c.AreaPassword != "", c.DomainPassword != ""
	c.NewAreaPassword, c.ClearAreaPassword, c.NewDomainPassword, c.ClearDomainPassword = "", false, "", false
}

func presentIsisInterface(i *models.IsisInterface) {
	i.HasPassword = i.Password != ""
	i.NewPassword, i.ClearPassword = "", false
}

// isisIfaceUsers lists IS-IS when it runs on the interface named name.
func isisIfaceUsers(tx *gorm.DB, instanceID uint, name string) []string {
	var users []string
	var n int64
	tx.Model(&models.IsisInterface{}).Where("instance_id = ? AND name = ?", instanceID, name).Count(&n)
	if n > 0 {
		users = append(users, "IS-IS")
	}
	tx.Model(&models.IsisConfig{}).Where("instance_id = ? AND net_interface = ?", instanceID, name).Count(&n)
	if n > 0 {
		users = append(users, "IS-IS's NET")
	}
	return users
}
