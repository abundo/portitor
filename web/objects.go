// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/netobj"
	"github.com/abundo/portitor/models"
)

// Named hosts and prefixes, and address lists, which share their names.
// Other rows refer to them by name inside their address lists; renaming
// one rewrites those references, and one in use cannot be deleted.

// loadNames loads every host and address list.
func loadNames(tx *gorm.DB) ([]models.AddressObject, []models.AddressList, error) {
	var objs []models.AddressObject
	if err := tx.Find(&objs).Error; err != nil {
		return nil, nil, err
	}
	var lists []models.AddressList
	if err := tx.Find(&lists).Error; err != nil {
		return nil, nil, err
	}
	return objs, lists, nil
}

// nameSet resolves every host and address list.
func nameSet(tx *gorm.DB) (netobj.Set, error) {
	objs, lists, err := loadNames(tx)
	if err != nil {
		return netobj.Set{}, err
	}
	return netobj.New(objs, lists...), nil
}
