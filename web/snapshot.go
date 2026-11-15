// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"path/filepath"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/dbmigrate"
)

// A copy of portitor-config's state is an archive of files (copybundle.go), for
// a backup and for the HA replica. What a release that kept it all in a database
// file gave as a copy is a database with the configuration's files in its table
// config_snapshot: still read (readSnapshot), for a secondary updated before its
// primary.

// snapshotTable holds the configuration's files in a copy.
const snapshotTable = "config_snapshot"

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
// installation's candidate, and its ids this one's. With keepFirewalls (a
// backup) the firewalls stay this installation's, with the ids the
// deployments name them by: they are hosts with their agents, not the
// configuration; a replica's copy takes the primary's whole.
func (s *Server) takeSnapshot(ctx context.Context, files map[string][]byte, fix func(*datastore.Tree), keepFirewalls bool) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	tree := datastore.New(t.schema)
	if err := tree.UnmarshalJSON(files["candidate.json"]); err != nil {
		return restoreError("the backup's configuration: " + err.Error())
	}
	var mine *datastore.Tree
	var myIDs []struct {
		path, tbl string
		id        int64
	}
	if keepFirewalls {
		if mine, err = s.globalsTree(t); err != nil {
			return err
		}
		tree.CopyLists(mine, "firewall")
		ids, err := s.rec.IDs()
		if err != nil {
			return err
		}
		ids.Each("/firewall[", func(path, tbl string, id int64) {
			myIDs = append(myIDs, struct {
				path, tbl string
				id        int64
			}{path, tbl, id})
		})
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
	// The entries' ids are those of the copy (or, for a copy from before they
	// were a file, of its database).
	if err := s.rec.ImportState(files); err != nil {
		return err
	}
	if keepFirewalls {
		if err := s.rec.UpdateIDs(func(ids sqlmap.IDs) {
			var theirs []string
			ids.Each("/firewall[", func(path, _ string, _ int64) { theirs = append(theirs, path) })
			for _, p := range theirs {
				ids.Delete(p)
			}
			for _, m := range myIDs {
				ids.Set(m.path, m.tbl, m.id)
			}
		}); err != nil {
			return err
		}
	}
	if err := t.store.Replace(ctx, tree); err != nil {
		return err
	}
	// What runs of the global lists is the copy's; a copy from before they
	// were a file has them in its database, which is adopted again.
	if g, ok := files["global.json"]; ok {
		gt := datastore.New(t.schema)
		if err := gt.UnmarshalJSON(g); err != nil {
			return restoreError("the backup's global lists: " + err.Error())
		}
		if keepFirewalls {
			gt.CopyLists(mine, "firewall")
		}
		unlock, err := s.lockData()
		if err != nil {
			return err
		}
		defer unlock()
		if err := s.writeGlobals(t, gt); err != nil {
			return err
		}
		s.forgetRunning()
		return nil
	}
	// The lists are taken from the database again, over what runs (a backup
	// keeps the firewalls this installation has).
	if !keepFirewalls {
		if err := s.adoptFirewalls(ctx, t, true); err != nil {
			return err
		}
	}
	return s.adoptAccess(ctx, t, true)
}
