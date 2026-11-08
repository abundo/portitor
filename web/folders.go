// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"gorm.io/gorm"

	"github.com/abundo/portitor/models"
)

// Folders structure the hosts and the IP lists in the GUI. They nest,
// never reach the agent, and a folder that holds anything cannot be
// deleted.

// checkFolder checks that folder id, if set, exists and holds items of
// kind.
func checkFolder(tx *gorm.DB, id *uint, kind string) error {
	if id == nil {
		return nil
	}
	var f models.ObjectFolder
	if err := tx.First(&f, *id).Error; err != nil || f.Kind != kind {
		return bad("folder does not exist")
	}
	return nil
}

// itemFolder normalises an item's folder (0 is none) and checks it.
func itemFolder(tx *gorm.DB, id **uint, kind string) error {
	if *id != nil && **id == 0 {
		*id = nil
	}
	return checkFolder(tx, *id, kind)
}
