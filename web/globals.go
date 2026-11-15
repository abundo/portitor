// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
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

// accessLists are the global lists adoptAccess takes from the old tables.
var accessLists = []string{"ldap-server", "user", "role", "ldap-role-mapping"}

func (t *treeState) isGlobal(name string) bool { return slices.Contains(t.globals, name) }

// dataDir is the directory next to the database file, where global.json is.
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

// lockData takes the lock of the files next to the database that the
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

// adopted is the file that names the lists taken from the database's old
// tables (adoptions.json next to it), each once.
func (s *Server) adopted() (map[string]bool, string, error) {
	dir, err := s.dataDir()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, "adoptions.json")
	out := map[string]bool{}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return out, path, nil
	case err != nil:
		return nil, "", err
	}
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return nil, "", fmt.Errorf("adoptions.json: %w", err)
	}
	for _, n := range names {
		out[n] = true
	}
	return out, path, nil
}

// markAdopted notes that a list has been taken from the database.
func (s *Server) markAdopted(name string) error {
	done, path, err := s.adopted()
	if err != nil {
		return err
	}
	done[name] = true
	b, err := json.Marshal(slices.Sorted(maps.Keys(done)))
	if err != nil {
		return err
	}
	return datastore.WriteFile(path, b)
}

// accessTables are the old tables of the global lists, in the order their
// rows are added (a row names the entries before it).
var accessTables = []struct {
	table string
	rows  func(db *gorm.DB) ([]any, error)
}{
	{"ldap_servers", func(db *gorm.DB) ([]any, error) { return loadRows[models.LdapServer](db, "position, id") }},
	{"users", func(db *gorm.DB) ([]any, error) { return loadRows[models.User](db, "id") }},
	{"roles", func(db *gorm.DB) ([]any, error) { return loadRows[models.Role](db, "id") }},
	{"role_members", func(db *gorm.DB) ([]any, error) { return loadRows[models.RoleMember](db, "id") }},
	{"role_instances", func(db *gorm.DB) ([]any, error) { return loadRows[models.RoleInstance](db, "id") }},
	{"ldap_role_mappings", func(db *gorm.DB) ([]any, error) { return loadRows[models.LdapRoleMapping](db, "id") }},
}

func loadRows[T any](db *gorm.DB, order string) ([]any, error) {
	var rows []T
	if err := db.Order(order).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]any, len(rows))
	for i := range rows {
		out[i] = &rows[i]
	}
	return out, nil
}

// adoptAccess takes the users, their roles and the directory of the
// database's old tables into the tree, once: into global.json with the ids
// the rows had (a session carries a user's id) and the highest id each table
// ever gave (a deleted user's id is never given again, whatever cookie
// carries it), and into the candidate when that has none of the lists. force
// does it again for a database that was restored.
func (s *Server) adoptAccess(ctx context.Context, t *treeState, force bool) error {
	const marker = "access"
	done, _, err := s.adopted()
	if err != nil {
		return err
	}
	if done[marker] && !force {
		return nil
	}
	for _, name := range accessLists {
		if !t.isGlobal(name) {
			return nil // another set of global lists than this adoption knows
		}
	}
	acc := datastore.New(t.schema)
	add := t.mapping.NewAdder(s.rec, acc, sqlmap.Index{})
	var any bool
	for _, tb := range accessTables {
		if !s.db.Migrator().HasTable(tb.table) {
			continue
		}
		rows, err := tb.rows(s.db)
		if err != nil {
			return err
		}
		for _, row := range rows {
			tbl, r, err := confview.RowOf(row)
			if err != nil {
				return err
			}
			if _, err := add.Add(tbl, r); err != nil {
				return fmt.Errorf("adopting %s: %w", tb.table, err)
			}
			any = true
		}
	}
	// The highest id each table gave, deleted rows' too.
	seq := map[string]int64{}
	var seqRows []struct {
		Name string
		Seq  int64
	}
	if s.db.Migrator().HasTable("sqlite_sequence") {
		if err := s.db.Table("sqlite_sequence").Select("name, seq").Find(&seqRows).Error; err != nil {
			return err
		}
	}
	for _, r := range seqRows {
		seq[r.Name] = r.Seq
	}
	if err := s.rec.UpdateIDs(func(ids sqlmap.IDs) {
		for n, id := range add.Index() {
			ids.Set(datastore.PathOf(n).String(t.schema), add.Table(n), id)
		}
		for _, tb := range accessTables {
			ids.SetMax(tb.table, seq[tb.table])
		}
	}); err != nil {
		return err
	}
	if any {
		// What runs of the lists is what the database had.
		unlock, err := s.lockData()
		if err != nil {
			return err
		}
		run, err := s.globalsTree(t)
		if err == nil {
			run.CopyLists(acc, accessLists...)
			err = s.writeGlobals(t, run)
		}
		unlock()
		if err != nil {
			return err
		}
		s.forgetRunning()
		// The candidate has them too, unless it has some of its own.
		if err := t.store.EditRaw(ctx, func(work *datastore.Tree) error {
			// Whole, or not at all: the lists name each other. The roles the
			// candidate made for its virtual firewalls meanwhile stay.
			if !force && len(work.Root.Lists["user"]) > 0 {
				return nil // its own (a restore replaces them: they are the copy's)
			}
			own := work.Root.Lists["role"]
			work.CopyLists(acc, accessLists...)
			for _, r := range own {
				if work.Root.Entry("role", r.Keys()) == nil {
					work.Root.Lists["role"] = append(work.Root.Lists["role"], r)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return s.markAdopted(marker)
}

// adoptFirewalls takes the firewalls of the database's old table into the
// tree, once: into global.json with the ids they had (the deployments name
// them) and the highest id the table gave, their generations into the runtime
// file, and into the candidate when that has none. force does it again for a
// restored database (a restored old backup keeps this installation's own).
func (s *Server) adoptFirewalls(ctx context.Context, t *treeState, force bool) error {
	const marker = "firewalls"
	done, _, err := s.adopted()
	if err != nil {
		return err
	}
	if done[marker] && !force {
		return nil
	}
	if !t.isGlobal("firewall") || !s.db.Migrator().HasTable("firewalls") {
		return nil
	}
	rows, err := loadRows[models.Firewall](s.db, "id")
	if err != nil {
		return err
	}
	acc := datastore.New(t.schema)
	add := t.mapping.NewAdder(s.rec, acc, sqlmap.Index{})
	// A secondary names its primary: the primaries first (a promotion swaps
	// the pair's rows in place, so a secondary may have the lower id).
	for _, secondary := range []bool{false, true} {
		for _, r := range rows {
			f := r.(*models.Firewall)
			if (f.HAPrimaryID != nil) != secondary {
				continue
			}
			tbl, row, err := confview.RowOf(f)
			if err != nil {
				return err
			}
			if _, err := add.Add(tbl, row); err != nil {
				return fmt.Errorf("adopting firewall %s: %w", f.Name, err)
			}
		}
	}
	var seq int64
	if s.db.Migrator().HasTable("sqlite_sequence") {
		_ = s.db.Raw("SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence WHERE name = 'firewalls'").Scan(&seq).Error
	}
	if err := s.rec.UpdateIDs(func(ids sqlmap.IDs) {
		for n, id := range add.Index() {
			ids.Set(datastore.PathOf(n).String(t.schema), add.Table(n), id)
		}
		ids.SetMax("firewalls", seq)
	}); err != nil {
		return err
	}
	for _, r := range rows {
		f := r.(*models.Firewall)
		if f.Generation > 0 {
			if err := s.rec.SetGeneration(f.ID, f.Generation); err != nil {
				return err
			}
		}
	}
	if len(rows) > 0 {
		unlock, err := s.lockData()
		if err != nil {
			return err
		}
		run, err := s.globalsTree(t)
		if err == nil {
			run.CopyLists(acc, "firewall")
			err = s.writeGlobals(t, run)
		}
		unlock()
		if err != nil {
			return err
		}
		s.forgetRunning()
		if err := t.store.EditRaw(ctx, func(work *datastore.Tree) error {
			if len(work.Root.Lists["firewall"]) == 0 {
				work.CopyLists(acc, "firewall")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return s.markAdopted(marker)
}
