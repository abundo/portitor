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

// prepareInstanceBFD checks the instance's default BFD timers.
func prepareInstanceBFD(in *models.Instance) error {
	if m := in.BfdDetectMultiplier; m != 0 && (m < 2 || m > 255) {
		return bad("BFD: the default detect multiplier must be 2-255")
	}
	for _, t := range []struct {
		name string
		ms   int
	}{{"receive", in.BfdReceiveInterval}, {"transmit", in.BfdTransmitInterval}} {
		if t.ms != 0 && (t.ms < 10 || t.ms > 60000) {
			return bad(fmt.Sprintf("BFD: the default %s interval must be 10-60000 ms", t.name))
		}
	}
	return nil
}

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
