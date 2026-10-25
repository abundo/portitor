// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dbmigrate

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
)

// serviceRateLimits (migration 77) brings databases made by a development
// build in line with 76 as released. That build's 76 had the instances'
// dns_rate_limit, dhcp_rate_limit and ntp_rate_limit name a rate limit
// (TEXT) and no rate_limits.service: the rate limit a service named becomes
// the service's, a service without one gets one as 76 makes them, and the
// columns become switches, on where they named one. A database 76 made as
// released is left as it is.
var serviceRateLimits = func() *goose.Migration {
	m := goose.NewGoMigration(77, &goose.GoFunc{RunTx: serviceRateLimitsUp}, nil)
	m.Source = "00077_service_rate_limits.go" // the name goose logs
	return m
}()

func serviceRateLimitsUp(ctx context.Context, tx *sql.Tx) error {
	if ok, err := hasColumn(ctx, tx, "rate_limits", "service"); err != nil || ok {
		return err
	}
	services := []struct{ service, column, name, description string }{
		{"dns", "dns_rate_limit", "dns server", "What comes in to the DNS server"},
		{"dhcp", "dhcp_rate_limit", "dhcp server", "What comes in to the DHCP server"},
		{"ntp", "ntp_rate_limit", "ntp server", "What comes in to the NTP server"},
	}
	stmts := []string{
		`ALTER TABLE rate_limits ADD COLUMN service TEXT NOT NULL DEFAULT ''`,
		`CREATE UNIQUE INDEX rate_limits_service ON rate_limits (instance_id, service) WHERE service != ''`,
	}
	for _, s := range services {
		// A rate limit two services named stays the first one's.
		stmts = append(stmts,
			fmt.Sprintf(`UPDATE rate_limits SET service = '%s' WHERE service = '' AND NOT shape
				AND EXISTS (SELECT 1 FROM instances i WHERE i.id = rate_limits.instance_id AND i.%s = rate_limits.name)`, s.service, s.column),
			fmt.Sprintf(`INSERT INTO rate_limits (instance_id, name, description, rate, per, unit, connections, service)
				SELECT i.id, '%[1]s' || CASE WHEN EXISTS (SELECT 1 FROM rate_limits r WHERE r.instance_id = i.id AND r.name = '%[1]s')
					THEN ' (service)' ELSE '' END, '%[2]s', 1, 'second', 'mbit', true, '%[3]s'
				FROM instances i WHERE NOT EXISTS (SELECT 1 FROM rate_limits r WHERE r.instance_id = i.id AND r.service = '%[3]s')`,
				s.name, s.description, s.service),
			fmt.Sprintf(`ALTER TABLE instances RENAME COLUMN %[1]s TO %[1]s_name`, s.column),
			fmt.Sprintf(`ALTER TABLE instances ADD COLUMN %s BOOLEAN NOT NULL DEFAULT false`, s.column),
			fmt.Sprintf(`UPDATE instances SET %[1]s = (%[1]s_name != '')`, s.column),
			fmt.Sprintf(`ALTER TABLE instances DROP COLUMN %s_name`, s.column),
		)
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("%s: %w", s, err)
		}
	}
	return nil
}
