// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/glebarez/sqlite"
	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/schema"
)

// LegacyMarker is the row of config_snapshot (SnapshotTable) that says the
// candidate and ids.json in it were read from the configuration tables by
// migration 94, for portitor-config to take as its own at its first start
// (it deletes the table then).
const (
	SnapshotTable = "config_snapshot"
	LegacyMarker  = "legacy-import"
)

//go:embed drop_config_tables.sql
var dropConfigTables string

// configToTree (migration 94) moves the configuration from its tables into
// the tree and drops them. The tables' rows are read as the tree they map
// to (sqlmap.Import, by the YANG modules' px: extensions), with the entries'
// ids kept (config_ids, and the high-water marks of the lists keyed by a
// number), and written, with secrets, into config_snapshot: the database is
// all a migration has, and portitor-config's start (web.adoptLegacyConfig)
// takes the configuration from there into candidate.json and the live
// commit's file. A database whose tables hold no virtual firewall (a new
// one) leaves nothing to adopt.
var configToTree = func() *goose.Migration {
	m := goose.NewGoMigration(94, &goose.GoFunc{RunDB: configToTreeUp}, nil)
	m.Source = "00094_drop_config_tables.go" // the name goose logs
	return m
}()

func configToTreeUp(ctx context.Context, db *sql.DB) error {
	gdb, err := gorm.Open(sqlite.Dialector{Conn: db}, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	if err := exportConfig(gdb); err != nil {
		return fmt.Errorf("moving the configuration into the tree: %w", err)
	}
	// One connection: the pragma and the transaction are its own.
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, dropConfigTables); err != nil {
		return fmt.Errorf("dropping the configuration tables: %w", err)
	}
	return nil
}

// exportConfig reads the tables into config_snapshot, when they hold a
// virtual firewall.
func exportConfig(db *gorm.DB) error {
	if !db.Migrator().HasTable("instances") {
		return nil
	}
	root, err := schema.Load()
	if err != nil {
		return err
	}
	m, err := sqlmap.New(root)
	if err != nil {
		return err
	}
	tree, idx, err := m.Import(db)
	if err != nil {
		return err
	}
	instances := 0
	tree.Root.Walk(func(n *datastore.Node) {
		if n.IsEntry() && n.S.Name == "instance" {
			instances++
		}
	})
	if instances == 0 {
		return nil
	}
	data, err := tree.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	marks, err := m.HighWater(db)
	if err != nil {
		return err
	}
	ids, err := json.Marshal(marks)
	if err != nil {
		return err
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := m.SeedIDs(tx, tree, idx); err != nil {
			return err
		}
		if err := tx.Exec("CREATE TABLE IF NOT EXISTS " + SnapshotTable + " (name TEXT PRIMARY KEY, data BLOB NOT NULL)").Error; err != nil {
			return err
		}
		for name, b := range map[string][]byte{"candidate.json": data, "ids.json": ids, LegacyMarker: []byte("1")} {
			if err := tx.Exec("INSERT INTO "+SnapshotTable+" (name, data) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET data = excluded.data", name, b).Error; err != nil {
				return err
			}
		}
		slog.Info("the configuration read from its tables", "entries", len(idx))
		return nil
	})
}
