// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
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
