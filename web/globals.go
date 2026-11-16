// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// The global lists are the top-level lists that are committed apart from the
// deployed configuration (dev/design-no-database.md): what runs of them is
// the file global.json, not the live commit's configuration, so that a
// commit of one of them can be made at once and alone (a scoped commit),
// whatever state the deployed configuration is in: a deployment waiting for
// confirmation, or rolled back later, leaves them as they are. A full commit
// takes them from the candidate too, and the commit's own file holds them as
// history only.

// globalLists names them: the directory's servers, the users, the roles and
// the directory's group mappings (dev/design-no-database.md).
var globalLists = []string{"firewall", "ldap-server", "user", "role", "ldap-role-mapping"}

func (t *treeState) isGlobal(name string) bool { return slices.Contains(t.globals, name) }

// dataDir is the data directory, where global.json is.
func (s *Server) dataDir() (string, error) {
	dir, err := s.snapshotDir()
	if err != nil {
		return "", err
	}
	return filepath.Dir(dir), nil
}

// globalsStamp is global.json's, for the cache of running.
func (s *Server) globalsStamp() datastore.FileStamp {
	path, err := s.globalsPath()
	if err != nil {
		return datastore.FileStamp{}
	}
	return datastore.StampOf(path)
}

func (s *Server) globalsPath() (string, error) {
	dir, err := s.dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "global.json"), nil
}

// overlayGlobals makes the global lists of tree (a commit's configuration)
// those that run. With no global.json yet they are the commit's, and kept.
func (s *Server) overlayGlobals(t *treeState, tree *datastore.Tree) error {
	if len(t.globals) == 0 {
		return nil
	}
	path, err := s.globalsPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Running holds the cache's lock; two processes seeding write the same.
		return s.writeGlobalsFile(t, tree)
	case err != nil:
		return err
	}
	g := datastore.New(t.schema)
	if err := g.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("global.json: %w", err)
	}
	tree.CopyLists(g, t.globals...)
	return nil
}

// saveGlobals keeps the global lists of tree as those that run.
func (s *Server) saveGlobals(tree *datastore.Tree) error {
	t, err := s.tree()
	if err != nil {
		return err
	}
	unlock, err := s.lockData()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.writeGlobals(t, tree); err != nil {
		return err
	}
	s.forgetRunning()
	return nil
}

// writeGlobals writes global.json from the global lists of tree. A user whose
// password or role changed, or who is gone, has their sessions ended, however
// it was changed (the API, the CLI, NETCONF).
func (s *Server) writeGlobals(t *treeState, tree *datastore.Tree) error {
	if err := s.revokeChanged(t, tree); err != nil {
		return err
	}
	return s.writeGlobalsFile(t, tree)
}

// revokeChanged ends the sessions of the users that tree changes or removes
// against what runs now.
func (s *Server) revokeChanged(t *treeState, tree *datastore.Tree) error {
	if !t.isGlobal("user") {
		return nil
	}
	path, err := s.globalsPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	old := datastore.New(t.schema)
	if err := old.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("global.json: %w", err)
	}
	ov, err := s.viewOf(old)
	if err != nil {
		return err
	}
	nv, err := s.viewOf(tree)
	if err != nil {
		return err
	}
	now := map[string]models.User{}
	for _, u := range nv.Users {
		now[u.Username] = u
	}
	for _, u := range ov.Users {
		if n, ok := now[u.Username]; !ok || n.PasswordHash != u.PasswordHash || n.Role != u.Role {
			if _, err := s.rec.Revoke(u.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeGlobalsFile writes global.json from the global lists of tree.
func (s *Server) writeGlobalsFile(t *treeState, tree *datastore.Tree) error {
	if len(t.globals) == 0 {
		return nil
	}
	path, err := s.globalsPath()
	if err != nil {
		return err
	}
	g := datastore.New(t.schema)
	g.CopyLists(tree, t.globals...)
	// It holds every secret.
	data, err := g.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := datastore.WriteFile(path, data); err != nil {
		return err
	}
	globalsGen.Add(1)
	return nil
}

// lockData takes the lock of the files in the data directory that the
// processes of one installation share (a console command runs beside the
// daemon): held from reading what runs of the global lists to writing it.
// It is not re-entrant.
func (s *Server) lockData() (unlock func(), err error) {
	dir, err := s.dataDir()
	if err != nil {
		return nil, err
	}
	return datastore.LockDir(dir, ".globals.lock")
}

// scopedResult is what a scoped commit did.
type scopedResult struct {
	// Deployed: some firewall's document changed and was deployed (result).
	Deployed bool
	Result   *commitResult
	// Warning: the lists are committed, but the deployment failed (a firewall
	// that can't be reached, a change waiting for confirmation): it is made
	// at the next commit.
	Warning string
}

// commitScoped commits the named global lists of the candidate cand and
// nothing else: running with those lists from the candidate. They run at
// once. With deploy, when that changes a firewall's document it is deployed
// like any commit (the firewalls it changes only; a failure is a warning,
// the lists stay committed); otherwise, or with no change, nothing is applied
// and no commit is numbered: the documents follow at the next commit. Logins
// and what a user does to their own entry never deploy.
func (s *Server) commitScoped(ctx context.Context, user string, cand *datastore.Tree, scope []string, deploy bool) (*scopedResult, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	for _, name := range scope {
		if !t.isGlobal(name) {
			return nil, bad(name + " is not committed alone")
		}
	}
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	if _, err := s.commitGlobalsOf(ctx, t, func(base *datastore.Tree) error {
		base.CopyLists(cand, scope...)
		return nil
	}); err != nil || !deploy {
		return &scopedResult{}, err
	}
	// What runs now, the lists included, is what the documents are built from.
	base, err := t.store.Running(ctx)
	if err != nil {
		return nil, err
	}
	fws, err := s.firewalls()
	if err != nil {
		return nil, err
	}
	changed, _, err := s.commitTargets(builder.Input{Rec: s.rec, Tree: base}, fws, nil)
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		// The configuration can't be built into documents (it has problems
		// of its own, which this commit did not make).
		return &scopedResult{Warning: "committed, but not deployed: " + strings.Join(ve.Problems, "; ")}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(changed) == 0 {
		return &scopedResult{}, nil
	}
	res, err := s.deployLocked(ctx, user, nil, nil, base)
	if err != nil {
		return &scopedResult{Warning: "committed, but not deployed: " + err.Error()}, nil
	}
	return &scopedResult{Deployed: true, Result: res}, nil
}

// globalsTree is what runs of the global lists alone, read from global.json
// (an empty tree before there is one): not the deployed part, which a rename
// or a delete of something the live commit names would leave inconsistent with
// them, and which reading would need the firewalls for.
func (s *Server) globalsTree(t *treeState) (*datastore.Tree, error) {
	g := datastore.New(t.schema)
	path, err := s.globalsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return g, nil
	case err != nil:
		return nil, err
	}
	if err := g.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("global.json: %w", err)
	}
	return g, nil
}

// problemsOf are the schema's and confcheck's problems with a tree.
func (t *treeState) problemsOf(tree *datastore.Tree) []error {
	errs := tree.Validate()
	if t.store.Check != nil {
		errs = append(errs, t.store.Check(tree)...)
	}
	return errs
}

// commitGlobalsOf makes what runs of the global lists what change makes of
// them: read, changed, checked and written under the lock the processes of
// the installation share. Only the lists are read and checked, and only what
// the change adds is refused (a configuration that has problems already can
// still be changed). It returns the lists as they are then.
func (s *Server) commitGlobalsOf(ctx context.Context, t *treeState, change func(base *datastore.Tree) error) (*datastore.Tree, error) {
	unlock, err := s.lockData()
	if err != nil {
		return nil, err
	}
	defer unlock()
	base, err := s.globalsTree(t)
	if err != nil {
		return nil, err
	}
	before := t.problemsOf(base)
	if err := change(base); err != nil {
		return nil, err
	}
	if added := newProblems(before, t.problemsOf(base)); len(added) > 0 {
		return nil, &datastore.ValidationError{Problems: added}
	}
	// The ids of what the change made, before it runs.
	if _, err := s.rec.AssignIDs(t.mapping, base); err != nil {
		return nil, err
	}
	if err := s.writeGlobals(t, base); err != nil {
		return nil, err
	}
	s.forgetRunning()
	return base, nil
}

// message is how the CLI and NETCONF report a scoped commit.
func (r *scopedResult) message() string {
	switch {
	case r.Warning != "":
		return "Committed. " + r.Warning
	case r.Deployed:
		return fmt.Sprintf("Commit %d: %s.", r.Result.Commit, r.Result.Status)
	}
	return "Committed (nothing to deploy)."
}
