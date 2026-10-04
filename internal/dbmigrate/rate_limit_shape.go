// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

// rateLimitShape (migration 39) brings databases made by development
// builds in line with 36 as released: rate_limits gets the unit,
// connections and shape columns it lacks, and the shapers of a former
// migration 38 (a table of their own, which rules named in rules.shaper)
// become rate limits that shape. A database 36 made with them all is left
// as it is. 38 is skipped: a development database may have it applied.
var rateLimitShape = func() *goose.Migration {
	m := goose.NewGoMigration(39, &goose.GoFunc{RunTx: rateLimitShapeUp}, nil)
	m.Source = "00039_rate_limit_shape.go" // the name goose logs
	return m
}()

func hasColumn(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&n)
	return n > 0, err
}

func rateLimitShapeUp(ctx context.Context, tx *sql.Tx) error {
	for _, c := range []struct{ name, def string }{
		{"unit", "TEXT NOT NULL DEFAULT ''"},
		{"connections", "BOOLEAN NOT NULL DEFAULT false"},
		{"shape", "BOOLEAN NOT NULL DEFAULT false"},
	} {
		ok, err := hasColumn(ctx, tx, "rate_limits", c.name)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf(`ALTER TABLE rate_limits ADD COLUMN %s %s`, c.name, c.def)); err != nil {
				return err
			}
		}
	}

	var shapers int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'shapers'`).Scan(&shapers); err != nil {
		return err
	}
	if shapers > 0 {
		// A shaper whose name a rate limit of its instance has keeps the
		// rate limit; the rules that named the shaper keep their own.
		stmts := []string{
			`INSERT INTO rate_limits (instance_id, name, description, rate, unit, per, shape)
				SELECT instance_id, name, description, mbit, 'mbit', 'second', true FROM shapers s
				WHERE NOT EXISTS (SELECT 1 FROM rate_limits l WHERE l.instance_id = s.instance_id AND l.name = s.name)`,
			`DROP TABLE shapers`,
		}
		if ok, err := hasColumn(ctx, tx, "rules", "shaper"); err != nil {
			return err
		} else if ok {
			stmts = append([]string{`UPDATE rules SET rate_limit = shaper WHERE rate_limit = '' AND shaper <> ''`}, stmts...)
			stmts = append(stmts, `ALTER TABLE rules DROP COLUMN shaper`)
		}
		for _, s := range stmts {
			if _, err := tx.ExecContext(ctx, s); err != nil {
				return err
			}
		}
	}
	return nil
}
