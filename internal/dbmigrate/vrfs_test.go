// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"path/filepath"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Migration 53 turns the vrf interfaces of migration 52 into VRFs.
func TestVRFsMigration(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := p.UpTo(ctx, 52); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO instances (id, name) VALUES (1, 'main')`,
		`INSERT INTO interfaces (id, instance_id, name, kind) VALUES (1, 1, 'eth1', 'physical'), (2, 1, 'eth2', 'physical')`,
		`INSERT INTO interfaces (id, instance_id, name, kind, vrf_table, members, description) VALUES (3, 1, 'blue', 'vrf', 10, '["eth1"]', 'cust')`,
		`INSERT INTO routes (id, instance_id, destination, gateway, vrf_id) VALUES (7, 1, 'default', '192.0.2.1', 3)`,
		`INSERT INTO routes (id, instance_id, destination, gateway) VALUES (8, 1, '10.0.0.0/8', '192.0.2.2')`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var vrf struct {
		ID          uint
		Name        string
		RouteTable  int
		Description string
	}
	if err := db.Raw(`SELECT id, name, route_table, description FROM vrfs`).Scan(&vrf).Error; err != nil || vrf.Name != "blue" || vrf.RouteTable != 10 || vrf.Description != "cust" {
		t.Fatalf("vrf: %+v %v", vrf, err)
	}
	var ifs []struct{ Name, Vrf string }
	db.Raw(`SELECT name, vrf FROM interfaces ORDER BY name`).Scan(&ifs)
	if len(ifs) != 2 || ifs[0].Vrf != "blue" || ifs[1].Vrf != "" {
		t.Errorf("interfaces: %+v", ifs)
	}
	var routes []struct {
		ID    uint
		VrfID *uint
	}
	db.Raw(`SELECT id, vrf_id FROM routes ORDER BY id`).Scan(&routes)
	if len(routes) != 2 || routes[0].VrfID == nil || *routes[0].VrfID != vrf.ID || routes[1].VrfID != nil {
		t.Errorf("routes: %+v", routes)
	}
	var fk []struct{ Table string }
	db.Raw(`PRAGMA foreign_key_check`).Scan(&fk)
	if len(fk) > 0 {
		t.Errorf("foreign key check: %+v", fk)
	}
}
