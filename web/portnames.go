// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"regexp"

	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// Custom port names. NAT port fields take them next to the built-in ones
// (fwconfig.Services); the builder writes their numbers, so the agent never
// sees them. Renaming one rewrites the NAT rules, and one in use cannot be
// deleted.

var portNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

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
