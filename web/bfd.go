// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"

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
