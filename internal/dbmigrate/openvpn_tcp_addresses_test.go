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

// Migration 83 splits an adaptive OpenVPN server's prefixes as Expand did:
// the address's half for UDP, the other half's first address for TCP.
func TestOpenVPNTCPAddressesMigration(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := p.UpTo(ctx, 82); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO instances (id, name) VALUES (1, 'main'), (2, 'shop')`,
		`INSERT INTO interfaces (id, instance_id, name, kind, addresses) VALUES (1, 1, 'ovpn0', 'openvpn', '["10.8.0.1/24","fd00:8::1/64"]')`,
		`INSERT INTO interfaces (id, instance_id, name, kind, addresses, ovpn_mode) VALUES (2, 2, 'ovpn0', 'openvpn', '["10.8.0.1/24"]', 'udp')`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if _, err := p.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var ifs []struct{ Addresses, OvpnTcpAddresses string }
	db.Raw(`SELECT addresses, ovpn_tcp_addresses FROM interfaces ORDER BY id`).Scan(&ifs)
	if len(ifs) != 2 ||
		ifs[0].Addresses != `["10.8.0.1/25","fd00:8::1/65"]` || ifs[0].OvpnTcpAddresses != `["10.8.0.129/25","fd00:8::8000:0:0:1/65"]` ||
		ifs[1].Addresses != `["10.8.0.1/24"]` || ifs[1].OvpnTcpAddresses != `[]` {
		t.Errorf("interfaces: %+v", ifs)
	}
}
