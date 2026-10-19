// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// A bundle is one instance as rows: every row deleting the instance would
// delete (the tables that cascade from instances, and from those), the
// shared objects instances use by name (bundleShared), and the rows of
// other instances it refers to by id (a global DNS template), by name.
// It is read and written column by column from the schema, so a new
// table or column needs nothing here; both sides must have the same
// schema version. Its ids are the source's: import gives the rows new
// ones and follows them in the foreign keys. A bundle holds every secret
// of the instance, like a backup.
//
// Links (they join two instances) come with the instance's name at the
// other end: import makes a link when that instance is there by name and
// the link is not, so it comes with whichever of the two arrives last.
//
// Left out: the instance's role (import makes one) and what belongs to
// the installation (deployments, firewalls, known interfaces, users).

const bundleFormat = 1

// bundleShared are the tables of objects shared by all instances, which
// rules refer to by name: imported by name, reused when equal.
var bundleShared = []string{"object_folders", "address_objects", "address_lists", "services", "port_names", "ip_lists"}

// bundleSkip are tables that cascade from instances but are not
// configuration of one.
var bundleSkip = map[string]bool{"roles": true, "role_instances": true, "links": true}

type bundleRow = map[string]any

type Bundle struct {
	Format int   `json:"format"`
	Schema int64 `json:"schema"`
	// Instance is the instance's name in the source.
	Instance string `json:"instance"`
	// Tables hold the instance's rows by table, "instances" its own.
	Tables map[string][]bundleRow `json:"tables"`
	Shared map[string][]bundleRow `json:"shared"`
	// Refs are rows of other instances it refers to by id, found by name
	// on import.
	Refs map[string][]bundleRow `json:"refs"`
	// Links are its links, each with "other": the instance at the other
	// end, by name.
	Links []bundleRow `json:"links"`
	// Left lists what was left out.
	Left []string `json:"left"`
}

type fkey struct{ table, from, parent, onDelete string }

// schemaGraph is every table's foreign keys.
func schemaGraph(ctx context.Context, q querier) (map[string][]fkey, error) {
	tables, err := queryStrings(ctx, q, "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'goose_db_version' ORDER BY name")
	if err != nil {
		return nil, err
	}
	g := map[string][]fkey{}
	for _, t := range tables {
		g[t] = nil
		rows, err := q.QueryContext(ctx, `SELECT "table", "from", on_delete FROM pragma_foreign_key_list(?)`, t)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			k := fkey{table: t}
			if err := rows.Scan(&k.parent, &k.from, &k.onDelete); err != nil {
				rows.Close()
				return nil, err
			}
			g[t] = append(g[t], k)
		}
		rows.Close()
	}
	return g, nil
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ownedTables are the tables that cascade from instances, parents first.
func ownedTables(g map[string][]fkey) []string {
	owned := map[string]bool{"instances": true}
	order := []string{"instances"}
	for changed := true; changed; {
		changed = false
		for _, t := range slices.Sorted(maps.Keys(g)) {
			if owned[t] || bundleSkip[t] {
				continue
			}
			for _, k := range g[t] {
				if owned[k.parent] && k.onDelete == "CASCADE" && k.parent != t {
					owned[t], changed = true, true
					order = append(order, t)
					break
				}
			}
		}
	}
	// Parents before children by every owned foreign key (Kahn): the one
	// cycle (instances' ACME proxy certificate) is set after the insert.
	rest := order[1:]
	sorted := []string{"instances"}
	placed := map[string]bool{"instances": true}
	for len(rest) > 0 {
		var next []string
		for _, t := range rest {
			ready := true
			for _, k := range g[t] {
				if owned[k.parent] && !placed[k.parent] && k.parent != t {
					ready = false
				}
			}
			if ready {
				sorted = append(sorted, t)
				placed[t] = true
			} else {
				next = append(next, t)
			}
		}
		if len(next) == len(rest) {
			sorted = append(sorted, next...) // a cycle: left to the deferred keys
			break
		}
		rest = next
	}
	return sorted
}

func selectRows(ctx context.Context, q querier, query string, args ...any) ([]bundleRow, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []bundleRow{}
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := bundleRow{}
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				vals[i] = string(b)
			}
			r[c] = vals[i]
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func rowID(r bundleRow) int64 {
	switch v := r["id"].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	}
	return 0
}

// ExportBundle reads the instance's bundle.
func ExportBundle(ctx context.Context, db *gorm.DB, instanceID uint) (*Bundle, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	g, err := schemaGraph(ctx, sqlDB)
	if err != nil {
		return nil, err
	}
	var version int64
	if err := sqlDB.QueryRowContext(ctx, "SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&version); err != nil {
		return nil, err
	}
	b := &Bundle{Format: bundleFormat, Schema: version, Tables: map[string][]bundleRow{}, Shared: map[string][]bundleRow{}, Refs: map[string][]bundleRow{}, Left: []string{}}
	inst, err := selectRows(ctx, sqlDB, `SELECT * FROM instances WHERE id = ?`, instanceID)
	if err != nil {
		return nil, err
	}
	if len(inst) != 1 {
		return nil, bad("no such virtual firewall")
	}
	b.Instance, _ = inst[0]["name"].(string)
	b.Tables["instances"] = inst
	ids := map[string]map[int64]bool{"instances": {int64(instanceID): true}}
	order := ownedTables(g)
	for _, t := range order[1:] {
		var conds []string
		var args []any
		for _, k := range g[t] {
			if k.onDelete == "CASCADE" && ids[k.parent] != nil {
				for id := range ids[k.parent] {
					conds = append(conds, fmt.Sprintf("%q = ?", k.from))
					args = append(args, id)
				}
			}
		}
		if len(conds) == 0 {
			continue
		}
		rows, err := selectRows(ctx, sqlDB, fmt.Sprintf("SELECT * FROM %q WHERE %s ORDER BY id", t, strings.Join(conds, " OR ")), args...)
		if err != nil {
			return nil, err
		}
		b.Tables[t] = rows
		ids[t] = map[int64]bool{}
		for _, r := range rows {
			ids[t][rowID(r)] = true
		}
	}
	// Rows outside the instance it refers to: a global DNS template, its
	// SOA template and policy.
	for t, rows := range b.Tables {
		for _, k := range g[t] {
			if k.parent == "instances" || slices.Contains(bundleShared, k.parent) || !slices.Contains(order, k.parent) {
				continue
			}
			for _, r := range rows {
				id, ok := r[k.from].(int64)
				if !ok || ids[k.parent][id] || slices.ContainsFunc(b.Refs[k.parent], func(x bundleRow) bool { return rowID(x) == id }) {
					continue
				}
				ref, err := selectRows(ctx, sqlDB, fmt.Sprintf("SELECT * FROM %q WHERE id = ?", k.parent), id)
				if err != nil {
					return nil, err
				}
				b.Refs[k.parent] = append(b.Refs[k.parent], ref...)
			}
		}
	}
	for _, t := range bundleShared {
		rows, err := selectRows(ctx, sqlDB, fmt.Sprintf("SELECT * FROM %q ORDER BY id", t))
		if err != nil {
			return nil, err
		}
		b.Shared[t] = rows
	}
	links, err := selectRows(ctx, sqlDB, `SELECT l.*, CASE WHEN l.instance_a_id = ? THEN b.name ELSE a.name END AS other
		FROM links l JOIN instances a ON a.id = l.instance_a_id JOIN instances b ON b.id = l.instance_b_id
		WHERE l.instance_a_id = ? OR l.instance_b_id = ? ORDER BY l.name`, instanceID, instanceID, instanceID)
	if err != nil {
		return nil, err
	}
	b.Links = links
	return b, nil
}

// bundleConflict is a shared object the target has otherwise.
type bundleConflict struct{ msg string }

func (e *bundleConflict) Error() string { return e.msg }

// importOptions are a manager's push (portitor-config): the instance and
// the shared objects it brings are Manager's; an instance of the name
// Manager pushed before is replaced, a diverged one only with Overwrite.
type importOptions struct {
	Manager   string
	Overwrite bool
	// ReplaceLocal replaces this database's own instance of the name, on
	// the firewall (a manager taking a firewall's version).
	ReplaceLocal bool
	// LocalInstance keeps the instance this firewall's own while its
	// shared objects are Manager's (the host's configuration moving from
	// its manager).
	LocalInstance bool
}

// ImportBundle adds the bundle's instance as a new instance named name on
// the firewall, with its shared objects, and returns its id and the
// problems its configuration has (it is imported anyway). Ids are new.
func ImportBundle(ctx context.Context, db *gorm.DB, b *Bundle, name string, firewallID uint) (uint, []string, error) {
	return importBundle(ctx, db, b, name, firewallID, importOptions{})
}

func importBundle(ctx context.Context, db *gorm.DB, b *Bundle, name string, firewallID uint, opt importOptions) (uint, []string, error) {
	if b.Format != bundleFormat {
		return 0, nil, bad(fmt.Sprintf("bundle format %d, this version reads %d", b.Format, bundleFormat))
	}
	if len(b.Tables["instances"]) != 1 {
		return 0, nil, bad("the bundle holds no virtual firewall")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return 0, nil, err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	var version int64
	if err := conn.QueryRowContext(ctx, "SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&version); err != nil {
		return 0, nil, err
	}
	if version != b.Schema {
		return 0, nil, bad(fmt.Sprintf("the bundle is of schema version %d, this database %d; update both to the same version", b.Schema, version))
	}
	g, err := schemaGraph(ctx, conn)
	if err != nil {
		return 0, nil, err
	}
	// A manager replaces the instance it pushed before.
	var replace *models.Instance
	if opt.ReplaceLocal {
		var old models.Instance
		if err := db.Where("name = ? AND firewall_id = ?", name, firewallID).First(&old).Error; err != nil || old.IsDefault {
			return 0, nil, bad("no virtual firewall " + name + " on that firewall to replace")
		}
		replace = &old
	}
	if opt.Manager != "" && !opt.LocalInstance {
		var old models.Instance
		switch err := db.Where("name = ?", name).First(&old).Error; {
		case err == nil:
			switch {
			case old.ManagedBy != opt.Manager:
				return 0, nil, &bundleConflict{fmt.Sprintf("virtual firewall %s is this firewall's own, not %s's", name, opt.Manager)}
			case old.IsDefault:
				return 0, nil, &bundleConflict{fmt.Sprintf("virtual firewall %s is the host; it is not replaced", name)}
			case old.Diverged && !opt.Overwrite:
				return 0, nil, &bundleConflict{fmt.Sprintf("virtual firewall %s was changed here (break-glass); take this version or overwrite it", name)}
			}
			replace = &old
			if firewallID == 0 {
				firewallID = old.FirewallID
			}
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return 0, nil, err
		}
	}
	// The instance is checked as a new one would be (name, firewall,
	// virtual firewalls on).
	var fresh models.Instance
	fresh.Name, fresh.FirewallID = name, firewallID
	if err := db.Transaction(func(tx *gorm.DB) error { return prepareInstanceFirewall(tx, &fresh, nil) }); err != nil {
		return 0, nil, err
	}
	if replace != nil && replace.FirewallID != fresh.FirewallID {
		return 0, nil, bad("a pushed virtual firewall stays on its firewall")
	}
	// Its role goes with it; the members come back on the new one.
	var members []models.RoleMember
	if replace != nil {
		if err := db.Where("role_id IN (?)", db.Model(&models.Role{}).Select("id").Where("instance_id = ?", replace.ID)).Find(&members).Error; err != nil {
			return 0, nil, err
		}
	}
	if !fwconfig.ValidInstanceName(name) {
		return 0, nil, bad("name: lowercase letters and digits, starting with a letter, at most 12 characters")
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys = ON"); err != nil {
		return 0, nil, err
	}
	if replace != nil {
		// The cascade would delete the DNS templates in any order, and
		// those in use refuse it: zones, templates, then what they use.
		for _, t := range []string{"dns_zones", "dns_templates", "dns_soa_templates", "dns_dnssec_policies"} {
			if _, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %q WHERE instance_id = ?", t), replace.ID); err != nil {
				return 0, nil, err
			}
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM instances WHERE id = ?", replace.ID); err != nil {
			return 0, nil, err
		}
	}
	// newIDs[table][old id] = new id.
	newIDs := map[string]map[int64]int64{}
	mapID := func(t string, old, nw int64) {
		if newIDs[t] == nil {
			newIDs[t] = map[int64]int64{}
		}
		newIDs[t][old] = nw
	}
	cols := map[string][]string{}
	colsOf := func(t string) ([]string, error) {
		if c, ok := cols[t]; ok {
			return c, nil
		}
		c, err := queryStrings(ctx, tx, "SELECT name FROM pragma_table_info(?) ORDER BY cid", t)
		cols[t] = c
		return c, err
	}

	// Shared objects by name (folders by kind, parent and name), parents
	// first.
	for _, t := range bundleShared {
		rows := b.Shared[t]
		if t == "object_folders" {
			rows = foldersParentsFirst(rows)
		}
		for _, r := range rows {
			old := rowID(r)
			fixed := remapRow(r, g[t], newIDs)
			match := "name = ?"
			args := []any{r["name"]}
			if t == "object_folders" {
				match = "kind = ? AND name = ? AND parent_id IS ?"
				args = []any{r["kind"], r["name"], fixed["parent_id"]}
			}
			have, err := selectRows(ctx, tx, fmt.Sprintf("SELECT * FROM %q WHERE %s", t, match), args...)
			if err != nil {
				return 0, nil, err
			}
			c, err := colsOf(t)
			if err != nil {
				return 0, nil, err
			}
			fixed["managed_by"] = opt.Manager
			if len(have) > 0 {
				mine := opt.Manager != "" && have[0]["managed_by"] == opt.Manager
				switch {
				case mine && t != "object_folders":
					// The manager's: its values now.
					if err := updateRow(ctx, tx, t, c, rowID(have[0]), fixed); err != nil {
						return 0, nil, fmt.Errorf("%s %v: %w", t, r["name"], err)
					}
				case opt.Manager != "" && !mine && t != "object_folders":
					return 0, nil, &bundleConflict{fmt.Sprintf("%s %v exists here, not %s's; rename or remove it here", strings.TrimSuffix(strings.ReplaceAll(t, "_", " "), "s"), r["name"], opt.Manager)}
				case t != "object_folders" && !sameRow(have[0], fixed):
					return 0, nil, &bundleConflict{fmt.Sprintf("%s %v exists here with other values", strings.TrimSuffix(t, "s"), r["name"])}
				}
				mapID(t, old, rowID(have[0]))
				continue
			}
			id, err := insertRow(ctx, tx, t, c, fixed)
			if err != nil {
				return 0, nil, fmt.Errorf("%s %v: %w", t, r["name"], err)
			}
			mapID(t, old, id)
		}
	}
	// Rows of other instances it refers to, found by name.
	for t, rows := range b.Refs {
		for _, r := range rows {
			var id int64
			err := tx.QueryRowContext(ctx, fmt.Sprintf("SELECT id FROM %q WHERE name = ? AND global", t), r["name"]).Scan(&id)
			if err != nil {
				return 0, nil, &bundleConflict{fmt.Sprintf("it uses %s %v, which is not here (as a global one)", strings.TrimSuffix(strings.ReplaceAll(t, "_", " "), "s"), r["name"])}
			}
			mapID(t, rowID(r), id)
		}
	}

	var instID int64
	var deferred []func() error
	for _, t := range ownedTables(g) {
		c, err := colsOf(t)
		if err != nil {
			return 0, nil, err
		}
		for _, r := range b.Tables[t] {
			fixed := remapRow(r, g[t], newIDs)
			if t == "instances" {
				fixed["name"], fixed["firewall_id"], fixed["is_default"] = name, fresh.FirewallID, fresh.IsDefault
				fixed["managed_by"], fixed["diverged"] = opt.Manager, false
				if opt.LocalInstance {
					fixed["managed_by"] = ""
				}
				// Set once its certificate is in.
				if v := r["acme_proxy_certificate_id"]; v != nil {
					old := v
					fixed["acme_proxy_certificate_id"] = nil
					deferred = append(deferred, func() error {
						cid, ok := newIDs["certificates"][toInt(old)]
						if !ok {
							return nil
						}
						_, err := tx.ExecContext(ctx, "UPDATE instances SET acme_proxy_certificate_id = ? WHERE id = ?", cid, instID)
						return err
					})
				}
			}
			id, err := insertRow(ctx, tx, t, c, fixed)
			if err != nil {
				return 0, nil, fmt.Errorf("%s: %w", t, err)
			}
			mapID(t, rowID(r), id)
			if t == "instances" {
				instID = id
			}
		}
	}
	for _, f := range deferred {
		if err := f(); err != nil {
			return 0, nil, err
		}
	}
	// Links to an instance that is here by name, unless there already.
	for _, l := range b.Links {
		var other int64
		if err := tx.QueryRowContext(ctx, "SELECT id FROM instances WHERE name = ?", l["other"]).Scan(&other); err != nil {
			continue
		}
		var n int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM links WHERE name = ?", l["name"]).Scan(&n); err != nil {
			return 0, nil, err
		}
		if n > 0 {
			continue
		}
		row := maps.Clone(l)
		delete(row, "other")
		if toInt(l["instance_a_id"]) == rowID(b.Tables["instances"][0]) {
			row["instance_a_id"], row["instance_b_id"] = instID, other
		} else {
			row["instance_a_id"], row["instance_b_id"] = other, instID
		}
		c, err := colsOf("links")
		if err != nil {
			return 0, nil, err
		}
		if _, err := insertRow(ctx, tx, "links", c, row); err != nil {
			return 0, nil, fmt.Errorf("link %v: %w", l["name"], err)
		}
	}
	// Name a key the ids did not follow, rather than fail at commit.
	if bad, err := selectRows(ctx, tx, "SELECT * FROM pragma_foreign_key_check"); err == nil && len(bad) > 0 {
		return 0, nil, fmt.Errorf("import: a foreign key the bundle does not hold: %v", bad[0])
	}
	if err := tx.Commit(); err != nil {
		return 0, nil, fmt.Errorf("import: %w", err)
	}

	var in models.Instance
	if err := db.First(&in, instID).Error; err != nil {
		return 0, nil, err
	}
	if err := createInstanceRole(db, &in); err != nil {
		return 0, nil, err
	}
	if len(members) > 0 {
		var role models.Role
		if err := db.Where("instance_id = ?", in.ID).First(&role).Error; err != nil {
			return 0, nil, err
		}
		for _, m := range members {
			if err := db.Create(&models.RoleMember{RoleID: role.ID, UserID: m.UserID, Level: m.Level}).Error; err != nil {
				return 0, nil, err
			}
		}
	}
	var problems []string
	_, err = builder.BuildInstances(db, 0, map[string]bool{name: true})
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		problems = ve.Problems
	}
	return uint(instID), problems, nil
}

func toInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}

// remapRow is the row with its foreign keys turned into the new ids, and
// without its id.
func remapRow(r bundleRow, keys []fkey, newIDs map[string]map[int64]int64) bundleRow {
	out := maps.Clone(r)
	delete(out, "id")
	for _, k := range keys {
		v, ok := out[k.from]
		if !ok || v == nil {
			continue
		}
		if id, ok := newIDs[k.parent][toInt(v)]; ok {
			out[k.from] = id
		}
	}
	return out
}

// sameRow compares two rows of a shared table but for their ids, times
// and folders.
func sameRow(have, want bundleRow) bool {
	for k, v := range want {
		switch k {
		case "id", "created_at", "updated_at", "folder_id", "managed_by":
			continue
		}
		if !reflect.DeepEqual(normalizeValue(have[k]), normalizeValue(v)) {
			return false
		}
	}
	return true
}

func normalizeValue(v any) any {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case bool:
		if x {
			return int64(1)
		}
		return int64(0)
	case []byte:
		return string(x)
	}
	return v
}

func insertRow(ctx context.Context, tx *sql.Tx, t string, cols []string, r bundleRow) (int64, error) {
	var names, marks []string
	var args []any
	for _, c := range cols {
		v, ok := r[c]
		if !ok || c == "id" {
			continue
		}
		names = append(names, fmt.Sprintf("%q", c))
		marks = append(marks, "?")
		args = append(args, v)
	}
	res, err := tx.ExecContext(ctx, fmt.Sprintf("INSERT INTO %q (%s) VALUES (%s)", t, strings.Join(names, ", "), strings.Join(marks, ", ")), args...)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func updateRow(ctx context.Context, tx *sql.Tx, t string, cols []string, id int64, r bundleRow) error {
	var sets []string
	var args []any
	for _, c := range cols {
		v, ok := r[c]
		if !ok || c == "id" || c == "created_at" {
			continue
		}
		sets = append(sets, fmt.Sprintf("%q = ?", c))
		args = append(args, v)
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("UPDATE %q SET %s WHERE id = ?", t, strings.Join(sets, ", ")), append(args, id)...)
	return err
}

// foldersParentsFirst orders folders so each comes after its parent.
func foldersParentsFirst(rows []bundleRow) []bundleRow {
	var out []bundleRow
	done := map[int64]bool{}
	for len(out) < len(rows) {
		n := len(out)
		for _, r := range rows {
			id := rowID(r)
			if done[id] {
				continue
			}
			if p := r["parent_id"]; p == nil || done[toInt(p)] {
				out = append(out, r)
				done[id] = true
			}
		}
		if len(out) == n {
			break // a loop: left out
		}
	}
	return out
}

// handleExportBundle downloads a virtual firewall as a bundle (global
// admins: it holds its secrets).
func (s *Server) handleExportBundle(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	b, err := ExportBundle(c.Request().Context(), s.db, id)
	if err != nil {
		return dbError(c, err)
	}
	return c.JSON(http.StatusOK, b)
}

// handleImportBundle adds a bundle as a new virtual firewall.
func (s *Server) handleImportBundle(c *echo.Context) error {
	var req struct {
		Name       string  `json:"name"`
		FirewallID uint    `json:"firewall_id"`
		Bundle     *Bundle `json:"bundle"`
	}
	if err := c.Bind(&req); err != nil || req.Bundle == nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	id, problems, err := ImportBundle(c.Request().Context(), s.db, req.Bundle, strings.TrimSpace(req.Name), req.FirewallID)
	var conflict *bundleConflict
	switch {
	case errors.As(err, &conflict):
		return errJSON(c, http.StatusConflict, conflict.msg)
	case err != nil:
		return dbError(c, err)
	}
	if problems == nil {
		problems = []string{}
	}
	return c.JSON(http.StatusCreated, map[string]any{"id": id, "problems": problems, "left": req.Bundle.Left})
}
