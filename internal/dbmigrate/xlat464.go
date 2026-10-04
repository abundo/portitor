// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

// xlat464 (migration 46) brings databases made by a development build of
// 44 in line with 44 as released: that build gave instances a pref64
// column where interfaces have xlat464. The flag can't be moved, as it
// was per instance; the interfaces start with 464XLAT off.
var xlat464 = func() *goose.Migration {
	m := goose.NewGoMigration(46, &goose.GoFunc{RunTx: xlat464Up}, nil)
	m.Source = "00046_xlat464.go" // the name goose logs
	return m
}()

func xlat464Up(ctx context.Context, tx *sql.Tx) error {
	if ok, err := hasColumn(ctx, tx, "interfaces", "xlat464"); err != nil {
		return err
	} else if !ok {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE interfaces ADD COLUMN xlat464 BOOLEAN NOT NULL DEFAULT false`); err != nil {
			return err
		}
	}
	if ok, err := hasColumn(ctx, tx, "instances", "pref64"); err != nil {
		return err
	} else if ok {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE instances DROP COLUMN pref64`); err != nil {
			return err
		}
	}
	return nil
}
