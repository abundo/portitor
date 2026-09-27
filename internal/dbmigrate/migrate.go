// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dbmigrate applies the versioned Postgres schema (goose SQL under
// sql/). This is the schema's source of truth; the GORM models only map it.
// Run with `portitor-web migrate`; `start` never migrates.
package dbmigrate

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

//go:embed sql/*.sql
var migrationFS embed.FS

func Up(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	fsys, err := fs.Sub(migrationFS, "sql")
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys)
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
