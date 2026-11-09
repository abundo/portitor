// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"os"
	"path/filepath"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/dbmigrate"
)

// A copy of portitor-config's state in one file, for a backup and the HA
// replica: the database (VACUUM INTO), with the configuration's files
// (the candidate, ids.json) in its table config_snapshot, which only such
// a copy has.

// snapshotTable holds the configuration's files in a copy.
const snapshotTable = "config_snapshot"

// writeSnapshot writes the copy to path (which must not exist).
func (s *Server) writeSnapshot(ctx context.Context, path string) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	cand, err := t.store.Candidate(ctx)
	if err != nil {
		return err
	}
	data, err := cand.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	files := map[string][]byte{"candidate.json": data}
	if t.dir != "" {
		if ids, err := os.ReadFile(filepath.Join(t.dir, "ids.json")); err == nil {
			files["ids.json"] = ids
		}
	}
	if err := s.db.Exec("VACUUM INTO ?", path).Error; err != nil {
		return err
	}
	db, err := dbmigrate.Open(path, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	if sqlDB, err := db.DB(); err == nil {
		defer sqlDB.Close()
	}
	if err := db.Exec("CREATE TABLE " + snapshotTable + " (name TEXT PRIMARY KEY, data BLOB NOT NULL)").Error; err != nil {
		return err
	}
	for _, name := range []string{"candidate.json", "ids.json"} {
		if b, ok := files[name]; ok {
			if err := db.Exec("INSERT INTO "+snapshotTable+" (name, data) VALUES (?, ?)", name, b).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

// readSnapshot reads the configuration's files of the copy at path.
func readSnapshot(path string) (map[string][]byte, error) {
	db, err := dbmigrate.Open(path, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, restoreError("not a readable SQLite database: " + err.Error())
	}
	if sqlDB, err := db.DB(); err == nil {
		defer sqlDB.Close()
	}
	var check []string
	if err := db.Raw("PRAGMA integrity_check").Scan(&check).Error; err != nil || len(check) != 1 || check[0] != "ok" {
		return nil, restoreError("the backup database is damaged")
	}
	if !db.Migrator().HasTable(snapshotTable) {
		return nil, restoreError("the backup holds no configuration (it comes from a version that kept it in tables)")
	}
	var rows []struct {
		Name string
		Data []byte
	}
	if err := db.Table(snapshotTable).Find(&rows).Error; err != nil {
		return nil, restoreError("the backup's configuration: " + err.Error())
	}
	out := map[string][]byte{}
	for _, r := range rows {
		out[r.Name] = r.Data
	}
	if out["candidate.json"] == nil {
		return nil, restoreError("the backup holds no configuration")
	}
	return out, nil
}

// takeSnapshot makes the configuration of a copy (readSnapshot) this
// installation's candidate, and its ids.json this one's.
func (s *Server) takeSnapshot(ctx context.Context, files map[string][]byte, fix func(*datastore.Tree)) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	tree := datastore.New(t.schema)
	if err := tree.UnmarshalJSON(files["candidate.json"]); err != nil {
		return restoreError("the backup's configuration: " + err.Error())
	}
	if fix != nil {
		fix(tree)
	}
	if ids, ok := files["ids.json"]; ok && t.dir != "" {
		if err := datastore.WriteFile(filepath.Join(t.dir, "ids.json"), ids); err != nil {
			return err
		}
		t.idMarks = nil
	}
	if err := t.store.Replace(ctx, tree); err != nil {
		return err
	}
	return nil
}
