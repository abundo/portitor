// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/buildinfo"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/models"
)

// A backup is a snapshot of the whole database (VACUUM INTO), encrypted
// with an age passphrase because it holds every secret: `age -d` decrypts
// it outside Portitor. Restore also takes an unencrypted database file.

// backupMaxSize limits a restored database; the request carries it base64
// encoded in JSON.
const backupMaxSize = 256 << 20

const restorePath = "/api/backup/restore"

// restoreKeeps are tables that belong to this installation rather than to
// the firewall configuration: restore leaves them as they are.
var restoreKeeps = []string{"users", "deployments", "goose_db_version"}

var sqliteMagic = []byte("SQLite format 3\x00")

func (s *Server) handleBackup(c *echo.Context) error {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if len(req.Passphrase) < minPasswordLen {
		return errJSON(c, http.StatusBadRequest, fmt.Sprintf("passphrase must be at least %d characters", minPasswordLen))
	}
	dir, err := os.MkdirTemp("", "portitor-backup")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	snap := filepath.Join(dir, "snapshot.db")
	if err := s.db.Exec("VACUUM INTO ?", snap).Error; err != nil {
		return err
	}
	var out bytes.Buffer
	if err := encryptBackup(&out, snap, req.Passphrase); err != nil {
		return err
	}
	ver := buildinfo.Version
	if ver != "dev" && !strings.HasPrefix(ver, "v") {
		ver = "v" + ver
	}
	name := "portitor-" + ver + "-" + time.Now().Format("20060102-150405") + ".db.age"
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="`+name+`"`)
	slog.Info("backup downloaded", "user", currentUser(c).Username, "bytes", out.Len())
	return c.Stream(http.StatusOK, "application/octet-stream", &out)
}

func encryptBackup(w io.Writer, path, passphrase string) error {
	r, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc, err := age.Encrypt(w, r)
	if err != nil {
		return err
	}
	if _, err := io.Copy(enc, f); err != nil {
		return err
	}
	return enc.Close()
}

// decryptBackup returns the database file in data: plain SQLite, or age
// (binary or armored) encrypted with passphrase.
func decryptBackup(data []byte, passphrase string) ([]byte, error) {
	if bytes.HasPrefix(data, sqliteMagic) {
		return data, nil
	}
	var in io.Reader = bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte("age-encryption.org/")):
	case bytes.HasPrefix(bytes.TrimSpace(data), []byte(armor.Header)):
		in = armor.NewReader(bytes.NewReader(bytes.TrimSpace(data)))
	default:
		return nil, errors.New("not a Portitor backup (neither an age encrypted file nor an SQLite database)")
	}
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(in, id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, errors.New("wrong passphrase")
		}
		return nil, err
	}
	out, err := io.ReadAll(io.LimitReader(r, backupMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	if len(out) > backupMaxSize {
		return nil, errors.New("backup is too large")
	}
	if !bytes.HasPrefix(out, sqliteMagic) {
		return nil, errors.New("the decrypted backup is not an SQLite database")
	}
	return out, nil
}

func (s *Server) handleRestore(c *echo.Context) error {
	var req struct {
		Data       []byte `json:"data"` // base64
		Passphrase string `json:"passphrase"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	data, err := decryptBackup(req.Data, req.Passphrase)
	if err != nil {
		return errJSON(c, http.StatusBadRequest, err.Error())
	}
	dir, err := os.MkdirTemp("", "portitor-restore")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "restore.db")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}

	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	if dep, err := s.latestDeployment(); err != nil {
		return err
	} else if dep != nil && dep.Status == "pending" {
		return errJSON(c, http.StatusConflict, "a deployment is waiting for confirmation; confirm or roll it back first")
	}
	res, err := restoreDatabase(c.Request().Context(), s.db, path)
	if err != nil {
		var re restoreError
		if errors.As(err, &re) {
			return errJSON(c, http.StatusBadRequest, err.Error())
		}
		return err
	}
	slog.Info("backup restored", "user", currentUser(c).Username, "schema_version", res.SchemaVersion, "migrated", res.Migrated)
	return c.JSON(http.StatusOK, res)
}

// restoreError is a problem with the backup, not the server.
type restoreError string

func (e restoreError) Error() string { return string(e) }

type restoreResult struct {
	// SchemaVersion is the backup's schema version before migration.
	SchemaVersion int64 `json:"schema_version"`
	Migrated      bool  `json:"migrated"`
}

// restoreDatabase replaces the configuration in db with the database file
// at path, which it checks and migrates first. It copies every table in
// one transaction, except restoreKeeps and the agent connection and
// deployment generation in settings, which stay those of this
// installation (when it has an agent configured).
func restoreDatabase(ctx context.Context, db *gorm.DB, path string) (*restoreResult, error) {
	res, err := prepareRestore(path)
	if err != nil {
		return nil, err
	}
	var cur models.Settings
	if err := db.FirstOrCreate(&cur, models.Settings{ID: 1}).Error; err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	// ATTACH is per connection.
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	// The backup's schema must not run SQL functions (views, triggers).
	if _, err := conn.ExecContext(ctx, "PRAGMA trusted_schema = OFF"); err != nil {
		return nil, err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "PRAGMA trusted_schema = ON")
	if _, err := conn.ExecContext(ctx, "ATTACH DATABASE ? AS bk", path); err != nil {
		return nil, err
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), "DETACH DATABASE bk")

	tables, err := queryStrings(ctx, conn, "SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	cols := map[string][]string{}
	for _, t := range tables {
		if slices.Contains(restoreKeeps, t) {
			continue
		}
		mine, err := queryStrings(ctx, conn, "SELECT name FROM pragma_table_info(?, 'main') ORDER BY name", t)
		if err != nil {
			return nil, err
		}
		theirs, err := queryStrings(ctx, conn, "SELECT name FROM pragma_table_info(?, 'bk') ORDER BY name", t)
		if err != nil {
			return nil, err
		}
		if !slices.Equal(mine, theirs) {
			return nil, restoreError(fmt.Sprintf("the backup's table %s does not match this version's schema (only in the backup: %s; only here: %s)",
				t, missing(theirs, mine), missing(mine, theirs)))
		}
		var kind string
		if err := conn.QueryRowContext(ctx, "SELECT type FROM bk.sqlite_master WHERE name = ?", t).Scan(&kind); err != nil || kind != "table" {
			return nil, restoreError(fmt.Sprintf("the backup's %s is not a table", t))
		}
		cols[t] = mine
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// Checked at commit: rows go in table by table, in any order.
	if _, err := tx.ExecContext(ctx, "PRAGMA defer_foreign_keys = ON"); err != nil {
		return nil, err
	}
	// Every table is cleared before any is filled: ON DELETE CASCADE acts
	// at once, and would empty a table already filled.
	for _, t := range tables {
		if _, ok := cols[t]; !ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM main."`+t+`"`); err != nil {
			return nil, fmt.Errorf("clear %s: %w", t, err)
		}
	}
	for _, t := range tables {
		c, ok := cols[t]
		if !ok {
			continue
		}
		list := `"` + strings.Join(c, `", "`) + `"`
		// AUTOINCREMENT keeps its counter, so the ids of rows deleted
		// here are not reused (rule ids mark connections).
		if _, err := tx.ExecContext(ctx, `INSERT INTO main."`+t+`" (`+list+`) SELECT `+list+` FROM bk."`+t+`"`); err != nil {
			return nil, fmt.Errorf("restore %s: %w", t, err)
		}
	}
	// Users stay those of this installation: a membership of a user
	// deleted since the backup goes with that user.
	if _, err := tx.ExecContext(ctx, `DELETE FROM main.role_members WHERE user_id NOT IN (SELECT id FROM main.users)`); err != nil {
		return nil, err
	}
	gen := `UPDATE main.settings SET generation = max(generation, ?) WHERE id = 1`
	args := []any{cur.Generation}
	if cur.AgentURL != "" {
		gen = `UPDATE main.settings SET generation = max(generation, ?), agent_url = ?, agent_token = ?, agent_fingerprint = ? WHERE id = 1`
		args = append(args, cur.AgentURL, cur.AgentToken, cur.AgentFingerprint)
	}
	r, err := tx.ExecContext(ctx, gen, args...)
	if err != nil {
		return nil, err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO main.settings (id, agent_url, agent_token, agent_fingerprint, confirm_timeout, wg_endpoint_host, generation, updated_at)
			VALUES (1, ?, ?, ?, ?, ?, ?, ?)`, cur.AgentURL, cur.AgentToken, cur.AgentFingerprint, cur.ConfirmTimeout, cur.WgEndpointHost, cur.Generation, time.Now()); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}
	return res, nil
}

// prepareRestore checks the database file at path and migrates it to this
// version's schema.
func prepareRestore(path string) (*restoreResult, error) {
	bk, err := dbmigrate.Open(path, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, restoreError("not a readable SQLite database: " + err.Error())
	}
	sqlDB, err := bk.DB()
	if err != nil {
		return nil, err
	}
	defer sqlDB.Close()
	if err := bk.Exec("PRAGMA trusted_schema = OFF").Error; err != nil {
		return nil, restoreError("not a readable SQLite database: " + err.Error())
	}
	var check []string
	if err := bk.Raw("PRAGMA integrity_check").Scan(&check).Error; err != nil {
		return nil, restoreError("not a readable SQLite database: " + err.Error())
	}
	if len(check) != 1 || check[0] != "ok" {
		return nil, restoreError("the backup database is damaged: " + strings.Join(check, "; "))
	}
	current, latest, err := dbmigrate.Versions(bk)
	switch {
	case err != nil:
		return nil, restoreError("not a Portitor database: " + err.Error())
	case current == 0:
		return nil, restoreError("not a Portitor database")
	case current > latest:
		return nil, restoreError(fmt.Sprintf("the backup comes from a newer Portitor (schema %d, this version has %d); update first", current, latest))
	}
	res := &restoreResult{SchemaVersion: current}
	if current < latest {
		if err := dbmigrate.Up(bk); err != nil {
			return nil, restoreError("migrating the backup: " + err.Error())
		}
		res.Migrated = true
	}
	var bad []map[string]any
	if err := bk.Raw("PRAGMA foreign_key_check").Scan(&bad).Error; err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		return nil, restoreError(fmt.Sprintf("the backup has %d rows with broken references", len(bad)))
	}
	return res, nil
}

// missing lists the names in a that b lacks, or "none".
func missing(a, b []string) string {
	var out []string
	for _, n := range a {
		if !slices.Contains(b, n) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ", ")
}

func queryStrings(ctx context.Context, conn *sql.Conn, query string, args ...any) ([]string, error) {
	rows, err := conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
