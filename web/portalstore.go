// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// PortalStore is portitor-manager's configuration, kept as portitor-config keeps a
// firewall's: a tree of the portal's YANG module (portitor-portal.yang), with
// a candidate (candidate.json, a datastore.Store, which the GUI, `portitor-manager
// cli`, SSH CLI and NETCONF share) and what runs (portal.json, RFC 7951
// JSON). A commit makes the candidate run: the proxies and the witness
// follow.
type PortalStore struct {
	// Store is the candidate and its commits, for the CLI and NETCONF.
	Store *datastore.Store

	mu      sync.Mutex
	schema  *schema.Node
	path    string
	running *datastore.Tree
	seen    datastore.FileStamp
	subs    []func()
}

// PortalFile is what runs, in the data directory.
const PortalFile = "portal.json"

// portalOwner is the session the GUI's and the console commands' edits take.
const portalOwner = "portal"

// OpenPortalStore reads dir/portal.json; none yet is an empty configuration
// (Exists tells).
func OpenPortalStore(dir string) (*PortalStore, error) {
	root, err := schema.LoadPortal()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		return nil, errors.New("portitor-manager: no data directory")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &PortalStore{schema: root, path: filepath.Join(dir, PortalFile), running: datastore.New(root)}
	s.Store = datastore.NewStore(root, portalBackend{s}, dir)
	s.Store.Check = portalCheck
	if err := s.reread(); err != nil {
		return nil, err
	}
	return s, nil
}

// portalCheck is what is wrong with a configuration beyond the schema: the
// firewalls' addresses and fingerprints, and the witness strings.
func portalCheck(t *datastore.Tree) []error {
	var errs []error
	for _, e := range t.Root.Lists["firewall"] {
		f := PortalFirewall{Name: e.Leaf("name"), URL: e.Leaf("url"), Fingerprint: e.Leaf("fingerprint")}
		if err := CheckPortalFirewall(&f); err != nil {
			errs = append(errs, fmt.Errorf("firewall %s: %w", f.Name, err))
		}
	}
	// An HA firewall shares /fw/<name>/ with the firewalls.
	for _, e := range t.Root.Lists["cluster"] {
		ha := portalHAOf(e)
		if t.Root.Entry("firewall", []string{ha.Name}) != nil {
			errs = append(errs, fmt.Errorf("cluster %s: there is a firewall %s", ha.Name, ha.Name))
		}
		if err := CheckPortalHA(&ha); err != nil {
			errs = append(errs, fmt.Errorf("cluster %s: %w", ha.Name, err))
		}
	}
	for _, e := range t.Root.Lists["witness"] {
		w, err := ParseWitness(e.Leaf("string"))
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("witness %s: %w", e.Leaf("pair"), err))
		case w.Pair != e.Leaf("pair"):
			errs = append(errs, fmt.Errorf("witness %s: the string is of the cluster %s", e.Leaf("pair"), w.Pair))
		}
	}
	return errs
}

// portalBackend is the datastore's backend: what runs is portal.json.
type portalBackend struct{ s *PortalStore }

func (b portalBackend) Initial(ctx context.Context) (*datastore.Tree, error) { return b.Running(ctx) }

func (b portalBackend) Running(context.Context) (*datastore.Tree, error) {
	b.s.mu.Lock()
	defer b.s.mu.Unlock()
	if err := b.s.reread(); err != nil {
		return nil, err
	}
	return b.s.running.Clone(), nil
}

func (b portalBackend) Commit(_ context.Context, t *datastore.Tree, o datastore.CommitOptions) (string, error) {
	if o.Validate {
		return "the configuration is valid", nil
	}
	if o.Confirm != nil {
		return "", errors.New("the portal has nothing to roll back to: commit without confirmed")
	}
	s := b.s
	s.mu.Lock()
	data, err := t.JSON(datastore.JSONOptions{Secrets: true, Indent: true})
	if err == nil {
		err = datastore.WriteFile(s.path, data)
	}
	if err != nil {
		s.mu.Unlock()
		return "", err
	}
	s.running = t
	s.seen = datastore.StampOf(s.path)
	subs := append([]func(){}, s.subs...)
	s.mu.Unlock()
	for _, f := range subs {
		f()
	}
	return "committed", nil
}

// reread reads portal.json when another process (a console command beside
// the daemon) has committed; s.mu is held.
func (s *PortalStore) reread() error {
	stamp := datastore.StampOf(s.path)
	if stamp == s.seen && s.seen != (datastore.FileStamp{}) {
		return nil
	}
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		t := datastore.New(s.schema)
		if err := t.UnmarshalJSON(data); err != nil {
			return fmt.Errorf("%s: %w", s.path, err)
		}
		s.running = t
	case !os.IsNotExist(err):
		return err
	}
	s.seen = stamp
	return nil
}

// refresh reads portal.json again if it changed, and tells the listeners.
func (s *PortalStore) refresh() {
	s.mu.Lock()
	before := s.seen
	err := s.reread()
	changed := err == nil && s.seen != before
	subs := append([]func(){}, s.subs...)
	s.mu.Unlock()
	if changed {
		for _, f := range subs {
			f()
		}
	}
}

// Watch checks every few seconds whether another process committed
// (portitor-manager cli beside the daemon), until ctx is done.
func (s *PortalStore) Watch(ctx context.Context) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.refresh()
		}
	}
}

// Exists reports whether a configuration has been committed.
func (s *PortalStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Tree is a copy of what runs.
func (s *PortalStore) Tree() *datastore.Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.reread()
	return s.running.Clone()
}

// OnChange calls fn after every commit.
func (s *PortalStore) OnChange(fn func()) {
	s.mu.Lock()
	s.subs = append(s.subs, fn)
	s.mu.Unlock()
}

// Edit is a change of the GUI or a console command: made in the candidate,
// checked, and committed at once (with whatever else the candidate holds). A
// change that is not valid is refused and leaves the candidate as it was.
func (s *PortalStore) Edit(fn func(*datastore.Tree) error) error {
	ctx := context.Background()
	err := s.Store.Edit(ctx, portalOwner, func(t *datastore.Tree) error {
		if err := fn(t); err != nil {
			return err
		}
		if errs := t.Validate(); len(errs) > 0 {
			return errs[0]
		}
		if errs := portalCheck(t); len(errs) > 0 {
			return errs[0]
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, err = s.Store.Commit(ctx, datastore.CommitOptions{User: portalOwner, Owner: portalOwner})
	return err
}

// Firewalls are the firewall entries, in order.
func (s *PortalStore) Firewalls() []PortalFirewall {
	t := s.Tree()
	var out []PortalFirewall
	for _, e := range t.Root.Lists["firewall"] {
		out = append(out, PortalFirewall{
			Name: e.Leaf("name"), Description: e.Leaf("description"), URL: e.Leaf("url"),
			Fingerprint: e.Leaf("fingerprint"), SSHHostKey: e.Leaf("ssh-host-key"),
		})
	}
	return out
}

// portalHAOf is a cluster entry.
func portalHAOf(e *datastore.Node) PortalHA {
	ha := PortalHA{Name: e.Leaf("name"), Description: e.Leaf("description"), Witness: e.Leaf("witness") != "false"}
	host := func(role string) *PortalFirewall {
		c := e.Containers[role]
		if c == nil || c.Leaf("url") == "" {
			return nil
		}
		return &PortalFirewall{Name: ha.Name + "/" + role, URL: c.Leaf("url"), Fingerprint: c.Leaf("fingerprint"), SSHHostKey: c.Leaf("ssh-host-key")}
	}
	ha.Primary, ha.Secondary = host("primary"), host("secondary")
	return ha
}

// HAFirewalls are the HA firewalls, in order.
func (s *PortalStore) HAFirewalls() []PortalHA {
	t := s.Tree()
	var out []PortalHA
	for _, e := range t.Root.Lists["cluster"] {
		out = append(out, portalHAOf(e))
	}
	return out
}

// HAFirewall is one HA firewall; ok is false for none.
func (s *PortalStore) HAFirewall(name string) (PortalHA, bool) {
	e := s.Tree().Root.Entry("cluster", []string{name})
	if e == nil {
		return PortalHA{}, false
	}
	return portalHAOf(e), true
}

// PutHA adds an HA firewall or changes its description and witness flag,
// keeping its hosts.
func (s *PortalStore) PutHA(ha PortalHA) error {
	return s.Edit(func(t *datastore.Tree) error {
		e := t.Root.Entry("cluster", []string{ha.Name})
		if e == nil {
			if t.Root.Entry("firewall", []string{ha.Name}) != nil {
				return fmt.Errorf("there is a firewall %s already", ha.Name)
			}
			e = t.Root.AddEntry(t.Root.S.Child("cluster"), map[string]string{"name": ha.Name})
		}
		delete(e.Leaves, "description")
		if ha.Description != "" {
			e.Leaves["description"] = ha.Description
		}
		e.Leaves["witness"] = fmt.Sprint(ha.Witness)
		return nil
	})
}

// SetHAHost sets (h nil: removes) the host of an HA firewall in role
// ("primary" or "secondary").
func (s *PortalStore) SetHAHost(name, role string, h *PortalFirewall) error {
	return s.Edit(func(t *datastore.Tree) error {
		e := t.Root.Entry("cluster", []string{name})
		if e == nil {
			return fmt.Errorf("there is no cluster firewall %s", name)
		}
		if role != "primary" && role != "secondary" {
			return fmt.Errorf("role %q: primary or secondary", role)
		}
		if h == nil {
			delete(e.Containers, role)
			return nil
		}
		c := e.AddContainer(e.S.Child(role))
		c.Leaves = map[string]string{"url": h.URL}
		for k, v := range map[string]string{"fingerprint": h.Fingerprint, "ssh-host-key": h.SSHHostKey} {
			if v != "" {
				c.Leaves[k] = v
			}
		}
		return nil
	})
}

// DeleteHA removes an HA firewall from the portal (the pair is not changed).
func (s *PortalStore) DeleteHA(name string) error {
	return s.Edit(func(t *datastore.Tree) error {
		return t.Delete(datastore.Path{{Name: "cluster", Keys: []string{name}}})
	})
}

// Witnesses are the witness strings.
func (s *PortalStore) Witnesses() []string {
	t := s.Tree()
	var out []string
	for _, e := range t.Root.Lists["witness"] {
		out = append(out, e.Leaf("string"))
	}
	return out
}

// PutFirewall adds or replaces a firewall (by name), at the end when new.
func (s *PortalStore) PutFirewall(f PortalFirewall) error {
	return s.Edit(func(t *datastore.Tree) error {
		leaves := map[string]string{"name": f.Name, "url": f.URL}
		for k, v := range map[string]string{"description": f.Description, "fingerprint": f.Fingerprint, "ssh-host-key": f.SSHHostKey} {
			if v != "" {
				leaves[k] = v
			}
		}
		fw := t.Root.S.Child("firewall")
		if t.Root.Entry("cluster", []string{f.Name}) != nil {
			return fmt.Errorf("there is a cluster firewall %s already", f.Name)
		}
		if e := t.Root.Entry("firewall", []string{f.Name}); e != nil {
			e.Leaves = leaves
			return nil
		}
		t.Root.AddEntry(fw, leaves)
		return nil
	})
}

// DeleteFirewall removes a firewall.
func (s *PortalStore) DeleteFirewall(name string) error {
	return s.Edit(func(t *datastore.Tree) error {
		return t.Delete(datastore.Path{{Name: "firewall", Keys: []string{name}}})
	})
}

// PutWitness adds a witness string (the pair is its own).
func (s *PortalStore) PutWitness(str string) error {
	w, err := ParseWitness(str)
	if err != nil {
		return err
	}
	return s.Edit(func(t *datastore.Tree) error {
		leaves := map[string]string{"pair": w.Pair, "string": w.String()}
		if e := t.Root.Entry("witness", []string{w.Pair}); e != nil {
			e.Leaves = leaves
			return nil
		}
		t.Root.AddEntry(t.Root.S.Child("witness"), leaves)
		return nil
	})
}

// DeleteWitness removes a pair's witness string.
func (s *PortalStore) DeleteWitness(pair string) error {
	return s.Edit(func(t *datastore.Tree) error {
		return t.Delete(datastore.Path{{Name: "witness", Keys: []string{pair}}})
	})
}

// PasswordHash is a user's bcrypt hash; ok is false for no such user.
func (s *PortalStore) PasswordHash(user string) (hash string, ok bool) {
	t := s.Tree()
	e := t.Root.Entry("user", []string{user})
	if e == nil {
		return "", false
	}
	return e.Leaf("password-hash"), true
}

// Users are the users' names.
func (s *PortalStore) Users() []string {
	t := s.Tree()
	var out []string
	for _, e := range t.Root.Lists["user"] {
		out = append(out, e.Leaf("name"))
	}
	return out
}

// SetPassword makes or changes a user.
func (s *PortalStore) SetPassword(user, hash string) error {
	return s.Edit(func(t *datastore.Tree) error {
		if e := t.Root.Entry("user", []string{user}); e != nil {
			e.Leaves["password-hash"] = hash
			return nil
		}
		t.Root.AddEntry(t.Root.S.Child("user"), map[string]string{"name": user, "password-hash": hash})
		return nil
	})
}
