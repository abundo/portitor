// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/models"
)

// What portitor-config keeps in files next to its database, not in it:
//
//   - entry-ids.json: the ids kept for the configuration's entries by path
//     (sqlmap.IDs). Part of a backup and of the replica's copy.
//   - state.json: the commit counter and the certificate portitor-config
//     serves. The installation's own: not in a backup.
//
// With no directory (a database in memory, tests) they are kept in memory
// alone. A directory that has no file yet is seeded from the database's old
// tables (config_ids and settings), which phase 5 of
// dev/design-no-database.md drops.
const (
	entryIDsFile = "entry-ids.json"
	stateFile    = "state.json"
)

// fileState is the two files, loaded once and written whole.
type fileState struct {
	mu  sync.Mutex
	dir string
	// seen are the files' stamps when they were last read or written here:
	// another process (a console command beside the daemon) may have
	// changed them since, and then they are read again.
	seen map[string]datastore.FileStamp

	idsLoaded bool
	ids       sqlmap.IDs

	stLoaded bool
	st       stateJSON

	depsLoaded bool
	deps       []models.Deployment
	depNext    uint

	nicsLoaded bool
	nics       map[uint][]string

	sessLoaded bool
	sess       map[uint]sessionRec
	gens       map[uint]int64
}

type stateJSON struct {
	Version          int   `json:"version"`
	LastCommit       int64 `json:"last_commit"`
	WebCertificateID *uint `json:"web_certificate_id"`
}

func (f *fileState) path(name string) string { return filepath.Join(f.dir, name) }

// begin takes the state's lock, and with write the lock the other processes
// that keep the files take too, and forgets what another process changed.
// The caller ends with the function it returns.
func (f *fileState) begin(write bool) (end func()) {
	f.mu.Lock()
	unlock := func() {}
	if write && f.dir != "" {
		// A directory that can't be locked is one that can't be written:
		// the write says so.
		if u, err := datastore.LockDir(f.dir, ".records.lock"); err == nil {
			unlock = u
		}
	}
	f.refresh()
	return func() {
		unlock()
		f.mu.Unlock()
	}
}

// refresh marks what another process changed as not loaded.
func (f *fileState) refresh() {
	if f.dir == "" {
		return
	}
	check := func(name string, loaded *bool) {
		now := datastore.StampOf(f.path(name))
		if f.seen == nil {
			f.seen = map[string]datastore.FileStamp{}
		}
		if was, ok := f.seen[name]; ok && was != now {
			*loaded = false
		}
		f.seen[name] = now
	}
	check(entryIDsFile, &f.idsLoaded)
	check(stateFile, &f.stLoaded)
	check(deploymentsFile, &f.depsLoaded)
	check(knownNICsFile, &f.nicsLoaded)
	check(sessionsFile, &f.sessLoaded)
}

// wrote notes that the file is as this process wrote it.
func (f *fileState) wrote(name string) {
	if f.seen == nil {
		f.seen = map[string]datastore.FileStamp{}
	}
	f.seen[name] = datastore.StampOf(f.path(name))
}

// loadIDs loads the entry ids (or seeds them from db's table), under f.mu.
func (f *fileState) loadIDs(db *gorm.DB) error {
	if f.idsLoaded {
		return nil
	}
	if f.dir != "" {
		switch b, err := os.ReadFile(f.path(entryIDsFile)); {
		case err == nil:
			var ids sqlmap.IDs
			if err := json.Unmarshal(b, &ids); err != nil {
				return err
			}
			f.ids, f.idsLoaded = ids, true
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	return f.seedIDs(db)
}

// seedIDs takes the ids from the database's table config_ids, and writes
// them, under f.mu.
func (f *fileState) seedIDs(db *gorm.DB) error {
	ids := sqlmap.NewIDs()
	if db != nil && db.Migrator().HasTable("config_ids") {
		var rows []struct {
			Path string
			Tbl  string
			ID   int64
		}
		if err := db.Table("config_ids").Select("path, tbl, id").Find(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			ids.Set(r.Path, r.Tbl, r.ID)
		}
	}
	return f.setIDs(ids)
}

// setIDs keeps ids, in memory and in the file, under f.mu.
func (f *fileState) setIDs(ids sqlmap.IDs) error {
	if f.dir != "" {
		b, err := json.Marshal(ids)
		if err != nil {
			return err
		}
		if err := datastore.WriteFile(f.path(entryIDsFile), b); err != nil {
			return err
		}
		f.wrote(entryIDsFile)
	}
	f.ids, f.idsLoaded = ids, true
	return nil
}

// loadState loads the state (or seeds it from db's table settings), under
// f.mu.
func (f *fileState) loadState(db *gorm.DB) error {
	if f.stLoaded {
		return nil
	}
	if f.dir != "" {
		switch b, err := os.ReadFile(f.path(stateFile)); {
		case err == nil:
			if err := json.Unmarshal(b, &f.st); err != nil {
				return err
			}
			f.stLoaded = true
			return nil
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
	}
	st := stateJSON{Version: 1}
	if db != nil && db.Migrator().HasTable("settings") && db.Migrator().HasColumn("settings", "last_commit") {
		var row struct {
			LastCommit       int64
			WebCertificateID *uint
		}
		if err := db.Table("settings").Select("last_commit, web_certificate_id").Where("id = 1").Take(&row).Error; err == nil {
			st.LastCommit, st.WebCertificateID = row.LastCommit, row.WebCertificateID
		}
	}
	return f.setState(st)
}

// setState keeps st, in memory and in the file, under f.mu.
func (f *fileState) setState(st stateJSON) error {
	st.Version = 1
	if f.dir != "" {
		b, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if err := datastore.WriteFile(f.path(stateFile), b); err != nil {
			return err
		}
		f.wrote(stateFile)
	}
	f.st, f.stLoaded = st, true
	return nil
}

// lastDeployedCommit is the highest commit with a configuration kept in
// dir/deployed (<commit>-config.json), 0 for none.
func (f *fileState) lastDeployedCommit() int64 {
	if f.dir == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join(f.dir, "deployed"))
	if err != nil {
		return 0
	}
	var top int64
	for _, e := range entries {
		n, ok := strings.CutSuffix(e.Name(), "-config.json")
		if !ok {
			continue
		}
		if c, err := strconv.ParseInt(n, 10, 64); err == nil && c > top {
			top = c
		}
	}
	return top
}
