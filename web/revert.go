// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/dbmigrate"
)

// Every deployment keeps a snapshot of the database it was built from
// (<db dir>/deployed/<generation>.db), so "Revert" can throw away the
// uncommitted changes: it restores the live deployment's snapshot the way a
// backup restore does. The document cannot be turned back into rows.

// snapshotKeep is how many of the latest live deployments keep a snapshot;
// rolling back a pending one makes an older one live again.
const snapshotKeep = 5

// snapshotDir is the directory next to the database file.
func (s *Server) snapshotDir() (string, error) {
	var rows []struct {
		Name string
		File string
	}
	if err := s.db.Raw("PRAGMA database_list").Scan(&rows).Error; err != nil {
		return "", err
	}
	for _, r := range rows {
		if r.Name == "main" && r.File != "" {
			return filepath.Join(filepath.Dir(r.File), "deployed"), nil
		}
	}
	return "", errors.New("the database has no file")
}

func snapshotPath(dir string, gen int64) string {
	return filepath.Join(dir, strconv.FormatInt(gen, 10)+".db")
}

// takeSnapshot writes the database to a temporary file in the snapshot
// directory; keepSnapshot or os.Remove finishes it.
func (s *Server) takeSnapshot(gen int64) (string, error) {
	dir, err := s.snapshotDir()
	if err != nil {
		return "", err
	}
	// Snapshots hold every secret, like the database.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp := snapshotPath(dir, gen) + ".tmp"
	os.Remove(tmp)
	if err := s.db.Exec("VACUUM INTO ?", tmp).Error; err != nil {
		return "", fmt.Errorf("snapshot: %w", err)
	}
	return tmp, nil
}

// openSnapshot opens a snapshot for reading; close it with closeDB.
func openSnapshot(path string) (*gorm.DB, error) {
	return dbmigrate.Open(path, &gorm.Config{Logger: logger.Discard})
}

func closeDB(db *gorm.DB) {
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.Close()
	}
}

// keepSnapshot moves the temporary snapshot into place and removes the
// snapshots of all but the latest live deployments.
func (s *Server) keepSnapshot(tmp string, gen int64) {
	dir := filepath.Dir(tmp)
	if err := os.Rename(tmp, snapshotPath(dir, gen)); err != nil {
		slog.Warn("keeping the deployment snapshot", "err", err)
		os.Remove(tmp)
		return
	}
	s.pruneSnapshots()
}

// pruneSnapshots removes the snapshots and documents of all but the latest
// live deployments.
func (s *Server) pruneSnapshots() {
	dir, err := s.snapshotDir()
	if err != nil {
		return
	}
	var gens []int64
	s.db.Table("deployments").Where("status IN ?", []string{"applied", "pending", "confirmed"}).
		Order("generation desc").Limit(snapshotKeep).Pluck("generation", &gens)
	keep := map[string]bool{}
	for _, g := range gens {
		keep[strconv.FormatInt(g, 10)] = true
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		gen, ext, ok := strings.Cut(e.Name(), ".")
		if ok && (ext == "db" || ext == "json") && !keep[gen] {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// handleDeployRevert replaces the configuration with the one the firewall
// runs, discarding every change since the last commit.
func (s *Server) handleDeployRevert(c *echo.Context) error {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	live, err := s.liveDeployment()
	if err != nil {
		return err
	}
	if live == nil {
		return errJSON(c, http.StatusConflict, "nothing has been committed yet")
	}
	dir, err := s.snapshotDir()
	if err != nil {
		return err
	}
	src, err := os.Open(snapshotPath(dir, live.Generation))
	if errors.Is(err, os.ErrNotExist) {
		if len(live.Instances) > 0 {
			return errJSON(c, http.StatusConflict, fmt.Sprintf("generation %d deployed only some virtual firewalls (%s); revert works after a deploy of everything", live.Generation, strings.Join(live.Instances, ", ")))
		}
		return errJSON(c, http.StatusConflict, fmt.Sprintf("generation %d has no saved configuration to revert to (it was committed by an older version)", live.Generation))
	} else if err != nil {
		return err
	}
	defer src.Close()

	// Restoring migrates the file; keep the snapshot as it was.
	tmpDir, err := os.MkdirTemp("", "portitor-revert")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	path := filepath.Join(tmpDir, "revert.db")
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if _, err := restoreDatabase(c.Request().Context(), s.db, path); err != nil {
		var re restoreError
		if errors.As(err, &re) {
			return errJSON(c, http.StatusConflict, err.Error())
		}
		return err
	}
	slog.Info("uncommitted changes reverted", "user", currentUser(c).Username, "generation", live.Generation)
	return c.JSON(http.StatusOK, map[string]any{"generation": live.Generation})
}
