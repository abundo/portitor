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

// BFD per interface of an instance, by name: renaming the interface
// rewrites it, and removing the interface removes it (web/ifzones.go).

func prepareBfdInterface(tx *gorm.DB, b, old *models.BfdInterface) error {
	if old != nil {
		b.InstanceID = old.InstanceID
	}
	if err := instanceExists(tx, b.InstanceID); err != nil {
		return err
	}
	b.Interface = strings.TrimSpace(b.Interface)
	parent, err := vrrpParent(tx, b.InstanceID, b.Interface)
	if err != nil {
		return err
	}
	if parent == nil {
		return bad(fmt.Sprintf("%q is not an interface of this virtual firewall", b.Interface))
	}
	if parent.Kind == fwconfig.KindLoopback {
		return bad("BFD is not for loopback interfaces")
	}
	if b.DetectMultiplier == 0 {
		b.DetectMultiplier = 3
	}
	if b.ReceiveInterval == 0 {
		b.ReceiveInterval = 300
	}
	if b.TransmitInterval == 0 {
		b.TransmitInterval = 300
	}
	b.Description = strings.TrimSpace(b.Description)
	if err := problems(fwconfig.CheckBFDInterface(b.BFD())); err != nil {
		return err
	}
	var n int64
	if err := tx.Model(&models.BfdInterface{}).Where("instance_id = ? AND interface = ? AND id <> ?", b.InstanceID, b.Interface, b.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("%s already has BFD settings", b.Interface))
	}
	return nil
}
