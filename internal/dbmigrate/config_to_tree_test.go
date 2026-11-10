// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openAt93 is a database migrated to just before the configuration tables
// go, which a release before the tree has as its own.
func openAt93(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "portitor.db"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), 93); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestConfigToTree(t *testing.T) {
	db := openAt93(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if err := db.Exec(q, args...).Error; err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO instances (id, name) VALUES (1, 'main')`)
	exec(`INSERT INTO interfaces (id, instance_id, name) VALUES (1, 1, 'eth0'), (2, 1, 'eth1')`)
	exec(`INSERT INTO rules (id, instance_id, chain) VALUES (7, 1, 'input')`)
	exec(`DELETE FROM rules WHERE id = 7`)
	exec(`INSERT INTO rules (id, instance_id, chain, description) VALUES (5, 1, 'input', 'web')`)
	// The default instance's template that the others may use is the
	// firewall's (top level); the other is the instance's own.
	exec(`INSERT INTO dns_soa_templates (id, instance_id, global, name, mname, rname) VALUES
		(1, 1, 1, 'shared-soa', 'ns.example.', 'hostmaster.example.'),
		(2, 1, 0, 'own-soa', 'ns.example.', 'hostmaster.example.')`)
	if err := Up(db); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"instances", "interfaces", "rules"} {
		if db.Migrator().HasTable(tbl) {
			t.Errorf("table %s is still there", tbl)
		}
	}
	var snap []struct {
		Name string
		Data []byte
	}
	if err := db.Table(SnapshotTable).Find(&snap).Error; err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, r := range snap {
		files[r.Name] = r.Data
	}
	if files[LegacyMarker] == nil {
		t.Fatalf("no marker: %v", files)
	}
	cand := string(files["candidate.json"])
	for _, want := range []string{`"eth0"`, `"eth1"`, `"web"`} {
		if !strings.Contains(cand, want) {
			t.Errorf("candidate lacks %s: %s", want, cand)
		}
	}
	var tree map[string]any
	if err := json.Unmarshal(files["candidate.json"], &tree); err != nil {
		t.Fatal(err)
	}
	names := func(v any) []string {
		var out []string
		list, _ := v.([]any)
		for _, e := range list {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m["name"].(string))
			}
		}
		return out
	}
	var top, own []string
	for k, v := range tree {
		if strings.HasSuffix(k, "dns-soa-template") {
			top = names(v)
		}
		if strings.HasSuffix(k, "instance") {
			inst, _ := v.([]any)
			for _, i := range inst {
				for k2, v2 := range i.(map[string]any) {
					if strings.HasSuffix(k2, "dns-soa-template") {
						own = names(v2)
					}
				}
			}
		}
	}
	if len(top) != 1 || top[0] != "shared-soa" || len(own) != 1 || own[0] != "own-soa" {
		t.Errorf("SOA templates: firewall's %v, instance's %v; want [shared-soa] and [own-soa]", top, own)
	}
	// A deleted rule's id is not given again.
	var marks map[string]uint64
	if err := json.Unmarshal(files["ids.json"], &marks); err != nil {
		t.Fatal(err)
	}
	if got := marks["/instance/rule"]; got < 7 {
		t.Errorf("rule high-water mark %d, want >= 7: %v", got, marks)
	}
	// The entries' ids are kept, by path.
	var n int64
	db.Raw(`SELECT COUNT(*) FROM config_ids WHERE tbl = 'interfaces'`).Scan(&n)
	if n != 2 {
		t.Errorf("config_ids has %d interfaces, want 2", n)
	}
}

// A database with no virtual firewall (a new one) has nothing to adopt.
func TestConfigToTreeEmpty(t *testing.T) {
	db := openAt93(t)
	if err := Up(db); err != nil {
		t.Fatal(err)
	}
	if db.Migrator().HasTable(SnapshotTable) {
		t.Error("an empty database left a snapshot")
	}
}
