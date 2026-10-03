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

// Folders structure the hosts and the IP lists in the GUI. They nest,
// never reach the agent, and a folder that holds anything cannot be
// deleted.

func prepareObjectFolder(tx *gorm.DB, f, old *models.ObjectFolder) error {
	f.Name = strings.TrimSpace(f.Name)
	if !fwconfig.ValidName(f.Name) {
		return bad("name: not empty, no control characters")
	}
	if old != nil && old.Kind != f.Kind {
		return bad("a folder cannot change kind")
	}
	if err := oneOf("kind", f.Kind, models.ObjectFolderHosts, models.ObjectFolderIpLists); err != nil {
		return err
	}
	if f.ParentID != nil && *f.ParentID == 0 {
		f.ParentID = nil
	}
	if err := checkFolder(tx, f.ParentID, f.Kind); err != nil {
		return err
	}
	// A folder cannot move into itself or into a folder inside it.
	if old != nil {
		for id := f.ParentID; id != nil; {
			if *id == f.ID {
				return bad("a folder cannot be inside itself")
			}
			var p models.ObjectFolder
			if err := tx.First(&p, *id).Error; err != nil {
				return err
			}
			id = p.ParentID
		}
	}
	var n int64
	q := tx.Model(&models.ObjectFolder{}).Where("kind = ? AND name = ? AND id <> ?", f.Kind, f.Name, f.ID)
	if f.ParentID == nil {
		q = q.Where("parent_id IS NULL")
	} else {
		q = q.Where("parent_id = ?", *f.ParentID)
	}
	if q.Count(&n); n > 0 {
		return bad(fmt.Sprintf("there is already a folder %s here", f.Name))
	}
	return nil
}

func deleteObjectFolder(tx *gorm.DB, f *models.ObjectFolder) error {
	var n int64
	tx.Model(&models.ObjectFolder{}).Where("parent_id = ?", f.ID).Count(&n)
	if n == 0 {
		tx.Model(&models.AddressObject{}).Where("folder_id = ?", f.ID).Count(&n)
	}
	if n == 0 {
		tx.Model(&models.IpList{}).Where("folder_id = ?", f.ID).Count(&n)
	}
	if n > 0 {
		return bad(fmt.Sprintf("folder %s is not empty", f.Name))
	}
	return nil
}

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
