// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"path/filepath"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/models"
)

// TestModelsMatchSchema checks that every field GORM maps has a column in
// the migrated schema, and that foreign keys are enforced.
func TestModelsMatchSchema(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := Up(db); err != nil {
		t.Fatal(err)
	}
	if err := Up(db); err != nil {
		t.Fatalf("second Up: %v", err)
	}
	for _, m := range models.All() {
		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(m); err != nil {
			t.Fatal(err)
		}
		table := stmt.Schema.Table
		if !db.Migrator().HasTable(table) {
			t.Errorf("table %s missing", table)
			continue
		}
		for _, f := range stmt.Schema.Fields {
			if f.DBName != "" && !db.Migrator().HasColumn(table, f.DBName) {
				t.Errorf("%s.%s missing", table, f.DBName)
			}
		}
	}

	var fk int
	db.Raw("PRAGMA foreign_keys").Scan(&fk)
	if fk != 1 {
		t.Error("foreign keys are not enforced")
	}
	err = db.Create(&models.Interface{InstanceID: 999, Name: "eth0"}).Error
	if err == nil {
		t.Error("insert with a dangling instance_id succeeded")
	}
}

// TestInterfaceAddressesMigration checks that migrations 9-11 move the
// addresses IPAM assigned to interfaces onto the interfaces, with the
// length of the smallest enclosing prefix, and keep IPAM rows that carry
// more than the assignment.
func TestInterfaceAddressesMigration(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO instances (id, name, is_default) VALUES (1, 'main', true)`,
		`INSERT INTO interfaces (id, instance_id, name) VALUES (1, 1, 'eth1'), (2, 1, 'wg0')`,
		`INSERT INTO ipam_prefixes (instance_id, prefix) VALUES (1, '192.168.0.0/16'), (1, '192.168.1.0/24'), (1, 'fd00:1::/64')`,
		`INSERT INTO ipam_addresses (id, instance_id, address, interface_id, dns_name) VALUES
			(1, 1, '192.168.1.1', 1, 'gw.home.arpa'),
			(2, 1, 'fd00:1::1', 1, ''),
			(3, 1, '10.99.0.1', 2, ''),
			(4, 1, '192.168.1.10', NULL, 'nas.home.arpa'),
			(9, 1, '192.168.1.99', NULL, '')`,
		`DELETE FROM ipam_addresses WHERE id = 9`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := Up(db); err != nil {
		t.Fatal(err)
	}

	var ifaces []models.Interface
	db.Order("id").Find(&ifaces)
	if got := ifaces[0].Addresses; len(got) != 2 || got[0] != "192.168.1.1/24" || got[1] != "fd00:1::1/64" {
		t.Errorf("eth1 addresses = %v", got)
	}
	if got := ifaces[1].Addresses; len(got) != 1 || got[0] != "10.99.0.1/32" {
		t.Errorf("wg0 addresses = %v (no prefix: a host address)", got)
	}
	var addrs []models.IpamAddress
	db.Order("id").Find(&addrs)
	if len(addrs) != 2 || addrs[0].Address != "192.168.1.1" || addrs[1].Address != "192.168.1.10" {
		t.Errorf("IPAM addresses left = %+v, want the two with DNS names", addrs)
	}
	if db.Migrator().HasColumn("ipam_addresses", "interface_id") {
		t.Error("ipam_addresses.interface_id is still there")
	}
	// The AUTOINCREMENT counter survives the rebuild: id 9 is not reused.
	a := models.IpamAddress{InstanceID: 1, Address: "192.168.1.20"}
	if err := db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}
	if a.ID != 10 {
		t.Errorf("new IPAM address id = %d, want 10", a.ID)
	}

	if _, err := p.DownTo(context.Background(), 8); err != nil {
		t.Fatalf("down to 8: %v", err)
	}
	var iface int64
	db.Raw(`SELECT interface_id FROM ipam_addresses WHERE address = 'fd00:1::1'`).Scan(&iface)
	if iface != 1 {
		t.Errorf("after down, fd00:1::1 is on interface %d, want 1", iface)
	}
}

// A DNS template's nameservers go from names to objects with addresses,
// and back.
func TestDnsNameserversMigration(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), 13); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO instances (id, name, is_default) VALUES (1, 'main', true)`,
		`INSERT INTO dns_soa_templates (id, name, mname, rname) VALUES (1, 'std', 'ns1.example.com', 'hostmaster.example.com')`,
		`INSERT INTO dns_templates (id, name, soa_template_id, nameservers) VALUES
			(1, 'two', 1, '["ns1.example.com","ns2.example.com"]'), (2, 'none', 1, '[]')`,
	} {
		if err := db.Exec(q).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := Up(db); err != nil {
		t.Fatal(err)
	}
	raw := func(id int) string {
		var s string
		db.Raw(`SELECT nameservers FROM dns_templates WHERE id = ?`, id).Scan(&s)
		return s
	}
	if got, want := raw(1), `[{"name":"ns1.example.com","address":""},{"name":"ns2.example.com","address":""}]`; got != want {
		t.Errorf("nameservers = %s, want %s", got, want)
	}
	if got := raw(2); got != "[]" {
		t.Errorf("empty nameservers = %s", got)
	}
	var tm models.DnsTemplate
	if err := db.First(&tm, 1).Error; err != nil || len(tm.Nameservers) != 2 || tm.Nameservers[1].Name != "ns2.example.com" {
		t.Errorf("template %+v: %v", tm, err)
	}

	// A second row of a name (its other address) is one name again after down.
	db.Exec(`UPDATE dns_templates SET nameservers = json_insert(nameservers, '$[#]', json_object('name', 'ns1.example.com', 'address', '2001:db8::1')) WHERE id = 1`)
	if _, err := p.DownTo(context.Background(), 13); err != nil {
		t.Fatalf("down to 13: %v", err)
	}
	if got, want := raw(1), `["ns1.example.com","ns2.example.com"]`; got != want {
		t.Errorf("after down, nameservers = %s, want %s", got, want)
	}
}

// TestRateLimitShapeMigration upgrades a database a development build
// left at 38: rate_limits without unit, connections and shape, and a
// shapers table that rules named.
func TestRateLimitShapeMigration(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), 37); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		`ALTER TABLE rate_limits DROP COLUMN shape`,
		`ALTER TABLE rate_limits DROP COLUMN connections`,
		`CREATE TABLE shapers (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, instance_id INTEGER NOT NULL REFERENCES instances(id) ON DELETE CASCADE,
			name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', mbit INTEGER NOT NULL DEFAULT 10, UNIQUE (instance_id, name))`,
		`ALTER TABLE rules ADD COLUMN shaper TEXT NOT NULL DEFAULT ''`,
		`INSERT INTO goose_db_version (version_id, is_applied) VALUES (38, true)`,
		`INSERT INTO instances (id, name) VALUES (1, 'main')`,
		`INSERT INTO shapers (instance_id, name, mbit) VALUES (1, 'guests', 20)`,
		`INSERT INTO rules (instance_id, chain, action, shaper) VALUES (1, 'forward', 'accept', 'guests')`,
	} {
		if err := db.Exec(s).Error; err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	if err := Up(db); err != nil {
		t.Fatal(err)
	}
	var l models.RateLimit
	if err := db.Where("name = ?", "guests").First(&l).Error; err != nil {
		t.Fatal(err)
	}
	if !l.Shape || l.Rate != 20 || l.Unit != "mbit" || l.Per != "second" {
		t.Errorf("shaper became %+v", l)
	}
	var r models.Rule
	db.First(&r)
	if r.RateLimit != "guests" {
		t.Errorf("rule names %q", r.RateLimit)
	}
	if db.Migrator().HasTable("shapers") || db.Migrator().HasColumn("rules", "shaper") {
		t.Error("shapers left behind")
	}
}
