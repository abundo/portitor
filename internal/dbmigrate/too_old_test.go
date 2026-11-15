// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openTemp(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// A database from before the schema that drops the configuration's tables
// is refused, untouched: its configuration is in those tables, and nothing
// reads them any more. A new database ends without them.
func TestUpRefusesTooOld(t *testing.T) {
	db := openTemp(t)
	p, err := provider(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), MinVersion-1); err != nil {
		t.Fatal(err)
	}
	if err := Up(db); !errors.Is(err, ErrTooOld) {
		t.Fatalf("Up on an old database: %v", err)
	}
	if cur, _, _ := Versions(db); cur != MinVersion-1 {
		t.Errorf("version %d after the refusal", cur)
	}
	if !db.Migrator().HasTable("instances") {
		t.Error("the refusal changed the database")
	}

	fresh := openTemp(t)
	if err := Up(fresh); err != nil {
		t.Fatal(err)
	}
	if fresh.Migrator().HasTable("instances") {
		t.Error("a new database kept the configuration tables")
	}
	if err := Up(fresh); err != nil {
		t.Fatalf("second Up: %v", err)
	}
}
