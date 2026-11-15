// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed drop_config_tables.sql
var dropConfigTables string

// dropConfigTables (migration 94) drops the configuration's tables: the
// configuration is the tree (candidate.json, deployed/<commit>-config.json).
// Releases up to 0.9.0 read the tables into the tree here; a database from
// before 0.9.0's schema (version 94) is refused by Up instead (MinVersion):
// upgrade to 0.9.0 first. It stays so that a new database, which still makes
// the tables with the migrations before it, ends without them.
var dropConfigTablesMigration = func() *goose.Migration {
	m := goose.NewGoMigration(MinVersion, &goose.GoFunc{RunDB: dropConfigTablesUp}, nil)
	m.Source = "00094_drop_config_tables.go" // the name goose logs
	return m
}()

func dropConfigTablesUp(ctx context.Context, db *sql.DB) error {
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
