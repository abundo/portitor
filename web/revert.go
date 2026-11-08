// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// Every commit keeps the configuration it deployed
// (<db dir>/deployed/<commit>-config.json): running is the live commit's,
// and "Revert" sets the candidate back to it.

// snapshotKeep is how many of the latest live commits keep their
// configuration; rolling back a pending one makes an older one live again.
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

// configPath is the file of a commit's configuration.
func configPath(dir string, commit int64) string {
	return filepath.Join(dir, strconv.FormatInt(commit, 10)+"-config.json")
}

// saveCommit keeps the configuration a commit deploys.
func (s *Server) saveCommit(t *datastore.Tree, commit int64) error {
	dir, err := s.snapshotDir()
	if err != nil {
		return err
	}
	// It holds every secret.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := t.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	return datastore.WriteFile(configPath(dir, commit), data)
}

// loadCommit is a commit's configuration; os.ErrNotExist when it isn't
// kept.
func (s *Server) loadCommit(root *schema.Node, commit int64) (*datastore.Tree, error) {
	dir, err := s.snapshotDir()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(configPath(dir, commit))
	if err != nil {
		return nil, err
	}
	t := datastore.New(root)
	if err := t.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("commit %d: %w", commit, err)
	}
	return t, nil
}

// pruneSnapshots removes the configurations and documents of all but the
// latest live commits.
func (s *Server) pruneSnapshots() {
	dir, err := s.snapshotDir()
	if err != nil {
		return
	}
	var commits []int64
	s.db.Table("deployments").Distinct("commit_id").Where("status IN ?", []string{"applied", "pending", "confirmed"}).
		Order("commit_id desc").Limit(snapshotKeep).Pluck("commit_id", &commits)
	// Each firewall's live document stays, however old.
	fws, _ := s.firewalls()
	for _, fw := range fws {
		if dep, _ := s.liveDeployment(fw.ID); dep != nil {
			commits = append(commits, dep.CommitID)
		}
	}
	keep := map[string]bool{}
	for _, c := range commits {
		keep[strconv.FormatInt(c, 10)] = true
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		base, ext, ok := strings.Cut(e.Name(), ".")
		commit, _, _ := strings.Cut(base, "-")
		if ok && (ext == "db" || ext == "json") && !keep[commit] {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// handleDeployRevert sets the candidate back to the configuration the
// firewalls run, discarding every change since the last commit.
func (s *Server) handleDeployRevert(c *echo.Context) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	live, err := s.liveCommit()
	if err != nil {
		return err
	}
	if live == 0 {
		return errJSON(c, http.StatusConflict, "nothing has been committed yet")
	}
	if err := t.store.Discard(c.Request().Context(), ""); err != nil {
		return errJSON(c, http.StatusConflict, err.Error())
	}
	slog.Info("uncommitted changes reverted", "user", currentUser(c).Username, "commit", live)
	return c.JSON(http.StatusOK, map[string]any{"generation": live})
}
