// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dbmigrate opens portitor-web's SQLite database and applies the
// versioned schema (goose SQL under sql/, and Go migrations for data moves
// SQL cannot compute, such as interface_addresses.go). This is the
// schema's source of truth; the GORM models only map it. Run with
// `portitor-web migrate`; `start` never migrates.
package dbmigrate

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"

	"github.com/glebarez/sqlite"
	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

//go:embed sql/*.sql
var migrationFS embed.FS

// Open opens the database file at path. Every connection enforces foreign
// keys (the schema's ON DELETE actions depend on it), waits for a lock
// instead of failing, and takes the write lock when a transaction begins,
// so two transactions that read and then write cannot deadlock.
func Open(path string, cfg *gorm.Config) (*gorm.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Set("_txlock", "immediate")
	return gorm.Open(sqlite.Open("file:"+path+"?"+q.Encode()), cfg)
}

func provider(db *gorm.DB) (*goose.Provider, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	fsys, err := fs.Sub(migrationFS, "sql")
	if err != nil {
		return nil, err
	}
	return goose.NewProvider(goose.DialectSQLite3, sqlDB, fsys, goose.WithGoMigrations(interfaceAddresses, rateLimitShape))
}

func Up(db *gorm.DB) error {
	provider, err := provider(db)
	if err != nil {
		return err
	}
	results, err := provider.Up(context.Background())
	if err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	if len(results) == 0 {
		slog.Info("goose: no pending migrations")
	}
	for _, r := range results {
		slog.Info("goose", "migration", r.String())
	}
	return nil
}

// Versions returns the database's schema version (0 when it has never
// been migrated) and the newest migration this binary has.
func Versions(db *gorm.DB) (current, latest int64, err error) {
	p, err := provider(db)
	if err != nil {
		return 0, 0, err
	}
	for _, src := range p.ListSources() {
		latest = max(latest, src.Version)
	}
	var n int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'goose_db_version'").Scan(&n).Error; err != nil || n == 0 {
		return 0, latest, err
	}
	current, err = p.GetDBVersion(context.Background())
	return current, latest, err
}
