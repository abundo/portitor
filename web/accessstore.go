// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/records"
	"github.com/abundo/portitor/models"
)

// The users, the roles and the directory's mappings are lists of the tree
// (global lists, globals.go). treeRecords is the records with those on the
// tree: what the rest of portitor-config asks of records.Store, answered from
// what runs of them, and what it changes written to what runs and to the
// candidate together (never one alone: the next full commit would undo it).
type treeRecords struct {
	records.Kept
	s *Server
}

var errReplica = errors.New("this is the HA secondary: its users are a read-only copy of the primary's")

// accessIndex is what runs of the users and roles, as the rows of the
// models, looked up by id and name.
type accessIndex struct {
	view      *confview.View
	users     []models.User
	byID      map[uint]int
	byName    map[string]int
	firewalls []models.Firewall // by id, without the generation
	roles     []models.Role     // with Members and Instances
	roleByID  map[uint]int
	grants    map[uint][]records.Grant
}

// accessCache is the index and what it was made from.
type accessCache struct {
	mu    sync.Mutex
	idx   *accessIndex
	stamp datastore.FileStamp
	gen   uint64
}

var globalsGen atomic.Uint64 // raised by every write of global.json here

func (s *Server) accessIndex(ctx context.Context) (*accessIndex, error) {
	c := &s.access
	c.mu.Lock()
	defer c.mu.Unlock()
	stamp, gen := s.globalsStamp(), globalsGen.Load()
	if c.idx != nil && c.stamp == stamp && c.gen == gen {
		return c.idx, nil
	}
	// From global.json alone: reading the deployed part needs the firewalls,
	// which are answered from this index.
	t, err := s.core()
	if err != nil {
		return nil, err
	}
	g, err := s.globalsTree(t)
	if err != nil {
		return nil, err
	}
	v, err := s.viewOf(g)
	if err != nil {
		return nil, err
	}
	idx := &accessIndex{view: v, byID: map[uint]int{}, byName: map[string]int{}, roleByID: map[uint]int{}, grants: map[uint][]records.Grant{}}
	idx.users = slices.Clone(v.Users)
	for i := range idx.users {
		u := &idx.users[i]
		u.TOTPEnabled = u.TOTPSecret != ""
		idx.byID[u.ID], idx.byName[u.Username] = i, i
	}
	// Roles: the instances' own first, then by name; members by id.
	roles := slices.Clone(v.Roles)
	slices.SortStableFunc(roles, func(a, b models.Role) int {
		switch {
		case (a.Instance != nil) != (b.Instance != nil):
			if a.Instance != nil {
				return -1
			}
			return 1
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	members := slices.Clone(v.RoleMembers)
	slices.SortStableFunc(members, func(a, b models.RoleMember) int { return int(a.ID) - int(b.ID) })
	grants := slices.Clone(v.RoleInstances)
	slices.SortStableFunc(grants, func(a, b models.RoleInstance) int {
		if a.Instance < b.Instance {
			return -1
		}
		if a.Instance > b.Instance {
			return 1
		}
		return 0
	})
	for i := range roles {
		r := &roles[i]
		r.Members = []models.RoleMember{}
		for _, m := range members {
			if m.RoleID == r.ID {
				r.Members = append(r.Members, m)
			}
		}
		switch {
		case r.Instance != nil:
			r.Instances = []string{*r.Instance}
		default:
			r.Instances = []string{}
			for _, g := range grants {
				if g.RoleID == r.ID {
					r.Instances = append(r.Instances, g.Instance)
				}
			}
		}
		idx.roleByID[r.ID] = i
		for _, m := range r.Members {
			if r.Instance != nil {
				idx.grants[m.UserID] = append(idx.grants[m.UserID], records.Grant{Instance: *r.Instance, Level: m.Level})
			}
			if r.Instance == nil {
				for _, in := range r.Instances {
					idx.grants[m.UserID] = append(idx.grants[m.UserID], records.Grant{Instance: in, Level: m.Level})
				}
			}
		}
	}
	idx.roles = roles
	idx.firewalls = slices.Clone(v.Firewalls)
	slices.SortStableFunc(idx.firewalls, func(a, b models.Firewall) int { return int(a.ID) - int(b.ID) })
	c.idx, c.stamp, c.gen = idx, stamp, gen
	return idx, nil
}

// ----- reads -----

func (t *treeRecords) Users() ([]models.User, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	out := slices.Clone(idx.users)
	ptrs := make([]*models.User, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	return out, t.Runtime(ptrs...)
}

func (t *treeRecords) User(id uint) (*models.User, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	i, ok := idx.byID[id]
	if !ok {
		return nil, records.ErrNotFound
	}
	u := idx.users[i]
	return &u, t.Runtime(&u)
}

func (t *treeRecords) UserNamed(name string) (*models.User, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	i, ok := idx.byName[name]
	if !ok {
		return nil, records.ErrNotFound
	}
	u := idx.users[i]
	return &u, t.Runtime(&u)
}

func (t *treeRecords) Roles() ([]models.Role, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]models.Role, len(idx.roles))
	for i, r := range idx.roles {
		out[i] = r
		out[i].Members = slices.Clone(r.Members)
		out[i].Instances = slices.Clone(r.Instances)
	}
	return out, nil
}

func (t *treeRecords) Role(id uint) (*models.Role, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	i, ok := idx.roleByID[id]
	if !ok {
		return nil, records.ErrNotFound
	}
	r := idx.roles[i]
	r.Members, r.Instances = nil, nil // without its members, as the row is
	return &r, nil
}

func (t *treeRecords) RoleMembers() ([]models.RoleMember, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	out := slices.Clone(idx.view.RoleMembers)
	slices.SortStableFunc(out, func(a, b models.RoleMember) int { return int(a.ID) - int(b.ID) })
	return out, nil
}

func (t *treeRecords) RoleMappings() ([]models.LdapRoleMapping, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	out := slices.Clone(idx.view.LdapRoleMappings)
	slices.SortStableFunc(out, func(a, b models.LdapRoleMapping) int { return int(a.ID) - int(b.ID) })
	return out, nil
}

func (t *treeRecords) UserGrants(userID uint) ([]records.Grant, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	return slices.Clone(idx.grants[userID]), nil
}

// ----- writes -----

// accessEnv is a tree and its rows when an edit starts. The ids are the
// entries' by path: what runs and the candidate each have them, and a rename
// made to one first leaves the other's entry without the id the change names.
// So the names the change found in what runs (names) are what it looks for in
// the candidate when the id does not find it.
type accessEnv struct {
	tree  *datastore.Tree
	v     *confview.View
	names *accessNames
}

// accessNames are the names of the entries by id, as what runs has them.
type accessNames struct {
	users, roles, firewalls map[uint]string
	members                 map[uint][2]string // role, user
}

func newAccessNames() *accessNames {
	return &accessNames{users: map[uint]string{}, roles: map[uint]string{}, firewalls: map[uint]string{}, members: map[uint][2]string{}}
}

// firewall is the firewall of the rows with the id (or, in the candidate, the
// name what runs had for it).
func (e *accessEnv) firewall(id uint) *models.Firewall {
	for i := range e.v.Firewalls {
		if e.v.Firewalls[i].ID == id {
			e.names.firewalls[id] = e.v.Firewalls[i].Name
			return &e.v.Firewalls[i]
		}
	}
	if name, ok := e.names.firewalls[id]; ok {
		for i := range e.v.Firewalls {
			if e.v.Firewalls[i].Name == name {
				return &e.v.Firewalls[i]
			}
		}
	}
	return nil
}

func (e *accessEnv) firewallNode(name string) *datastore.Node {
	return e.tree.Root.Entry("firewall", []string{name})
}

func (s *Server) accessEnvOf(tree *datastore.Tree, names *accessNames) (*accessEnv, error) {
	v, err := s.viewOf(tree)
	if err != nil {
		return nil, err
	}
	return &accessEnv{tree: tree, v: v, names: names}, nil
}

func (e *accessEnv) user(id uint) *models.User {
	for i := range e.v.Users {
		if e.v.Users[i].ID == id {
			e.names.users[id] = e.v.Users[i].Username
			return &e.v.Users[i]
		}
	}
	if name, ok := e.names.users[id]; ok {
		for i := range e.v.Users {
			if e.v.Users[i].Username == name {
				return &e.v.Users[i]
			}
		}
	}
	return nil
}

func (e *accessEnv) role(id uint) *models.Role {
	for i := range e.v.Roles {
		if e.v.Roles[i].ID == id {
			e.names.roles[id] = e.v.Roles[i].Name
			return &e.v.Roles[i]
		}
	}
	if name, ok := e.names.roles[id]; ok {
		for i := range e.v.Roles {
			if e.v.Roles[i].Name == name {
				return &e.v.Roles[i]
			}
		}
	}
	return nil
}

func (e *accessEnv) userNode(name string) *datastore.Node {
	return e.tree.Root.Entry("user", []string{name})
}
func (e *accessEnv) roleNode(name string) *datastore.Node {
	return e.tree.Root.Entry("role", []string{name})
}

// accessOp is a change of the users, roles or mappings of a tree. strict is
// the one of what runs: what isn't there is an error; in the candidate it is
// skipped (an admin may have deleted or renamed it there).
type accessOp func(e *accessEnv, strict bool) error

// editAccess makes op to what runs of the global lists and to the candidate,
// together. A replica's users are a copy.
func (s *Server) editAccess(ctx context.Context, op accessOp) (*datastore.Tree, error) {
	return s.editAccessAs(ctx, false, op)
}

// editAccessAs is editAccess; with onReplica it is also made on a replica (a
// promotion, which is what ends being one).
func (s *Server) editAccessAs(ctx context.Context, onReplica bool, op accessOp) (*datastore.Tree, error) {
	if !onReplica && s.isReplica() {
		return nil, errReplica
	}
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	names := newAccessNames()
	base, err := s.commitGlobalsOf(ctx, t, func(base *datastore.Tree) error {
		e, err := s.accessEnvOf(base, names)
		if err != nil {
			return err
		}
		return op(e, true)
	})
	if err != nil {
		return nil, err
	}
	s.bothTrees.Add(1) // a rename here is the one made to what runs too
	defer s.bothTrees.Add(-1)
	err = t.store.EditRaw(ctx, func(work *datastore.Tree) error {
		e, err := s.accessEnvOf(work, names)
		if err != nil {
			return err
		}
		return op(e, false)
	})
	return base, err
}

func userLeaves(u *models.User) map[string]string {
	l := map[string]string{"username": u.Username, "role": u.Role}
	put := func(k, v string) {
		if v != "" {
			l[k] = v
		}
	}
	put("full-name", u.FullName)
	put("email", u.Email)
	put("date-format", u.DateFormat)
	put("password-hash", u.PasswordHash)
	put("ldap-server", u.LdapServer)
	put("totp-secret", u.TOTPSecret)
	put("recovery-codes", u.RecoveryCodes)
	if u.TOTPRequired {
		l["totp-required"] = "true"
	}
	return l
}

func (t *treeRecords) CreateUser(u *models.User) error {
	base, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		if n := e.userNode(u.Username); n != nil {
			if strict {
				return records.ErrExists
			}
			n.Leaves = userLeaves(u)
			return nil
		}
		e.tree.Root.AddEntry(e.tree.Root.S.Child("user"), userLeaves(u))
		return nil
	})
	if err != nil {
		return err
	}
	return t.setID(base, "user", []string{u.Username}, &u.Base)
}

// setID reads the id the new entry was given.
func (t *treeRecords) setID(tree *datastore.Tree, list string, keys []string, b *models.Base) error {
	n := tree.Root.Entry(list, keys)
	if n == nil {
		return errors.New("the new entry is not there")
	}
	ids, err := t.IDs()
	if err != nil {
		return err
	}
	id, ok := ids.ID(datastore.PathOf(n).String(tree.Root.S))
	if !ok {
		return errors.New("the new entry has no id")
	}
	b.ID = uint(id)
	return nil
}

func (t *treeRecords) SaveUser(u *models.User, revoke bool) error {
	if revoke {
		v, err := t.Revoke(u.ID)
		if err != nil {
			return err
		}
		u.TokenVersion = v
	}
	_, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		old := e.user(u.ID)
		if old == nil {
			if strict {
				return records.ErrNotFound
			}
			return nil
		}
		n := e.userNode(old.Username)
		if u.Username != old.Username {
			if err := e.tree.Rename(datastore.PathOf(n), []string{u.Username}); err != nil {
				return err
			}
		}
		n.Leaves = userLeaves(u)
		return nil
	})
	return err
}

func (t *treeRecords) DeleteUser(id uint) error {
	// The sessions end, and the id's version stays above them.
	if _, err := t.Revoke(id); err != nil {
		return err
	}
	_, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		old := e.user(id)
		if old == nil {
			if strict {
				return records.ErrNotFound
			}
			return nil
		}
		// The memberships go with the user.
		for _, r := range e.tree.Root.Lists["role"] {
			if m := r.Entry("member", []string{old.Username}); m != nil {
				if err := e.tree.Delete(datastore.PathOf(m)); err != nil {
					return err
				}
			}
		}
		return e.tree.Delete(datastore.PathOf(e.userNode(old.Username)))
	})
	return err
}

// setUserLeaves sets (or, with "", removes) leaves of a user's entry.
func (t *treeRecords) setUserLeaves(u *models.User, leaves map[string]string) error {
	_, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		old := e.user(u.ID)
		if old == nil {
			if strict {
				return records.ErrNotFound
			}
			return nil
		}
		n := e.userNode(old.Username)
		for k, v := range leaves {
			if v == "" {
				delete(n.Leaves, k)
			} else {
				n.Leaves[k] = v
			}
		}
		return nil
	})
	return err
}

func (t *treeRecords) BeginTOTP(u *models.User, secret string) error {
	if err := t.SetTOTPPending(u.ID, secret); err != nil {
		return err
	}
	u.TOTPPending = secret
	return nil
}

func hashList(s string) []string {
	var l []string
	_ = json.Unmarshal([]byte(s), &l)
	return l
}

func (t *treeRecords) EnableTOTP(u *models.User, step int64, recoveryHashes string) error {
	secret := u.TOTPPending
	if err := t.setUserLeaves(u, map[string]string{"totp-secret": secret, "recovery-codes": recoveryHashes}); err != nil {
		return err
	}
	if err := t.EnableTOTPState(u.ID, step); err != nil {
		return err
	}
	u.TOTPSecret, u.RecoveryCodes, u.TOTPPending, u.TOTPLastStep = secret, recoveryHashes, "", step
	return nil
}

func (t *treeRecords) SetRecoveryCodes(u *models.User, hashes string) error {
	if err := t.setUserLeaves(u, map[string]string{"recovery-codes": hashes}); err != nil {
		return err
	}
	u.RecoveryCodes = hashes
	return t.ForgetRecoveryCodes(u.ID, hashList(hashes))
}

func (t *treeRecords) ClearTOTP(u *models.User) error {
	if err := t.setUserLeaves(u, map[string]string{"totp-secret": "", "recovery-codes": ""}); err != nil {
		return err
	}
	if err := t.ClearTOTPState(u.ID); err != nil {
		return err
	}
	u.TOTPSecret, u.RecoveryCodes, u.TOTPPending, u.TOTPLastStep = "", "", "", 0
	return nil
}

// UseRecoveryCode marks the code that is in current and not in rest used:
// the codes are configuration, which a login never writes.
func (t *treeRecords) UseRecoveryCode(userID uint, current, rest string) (bool, error) {
	left := hashList(rest)
	for _, h := range hashList(current) {
		if !slices.Contains(left, h) {
			return t.MarkRecoveryCodeUsed(userID, h)
		}
	}
	return false, nil
}

// ----- roles -----

func roleLeaves(r *models.Role) map[string]string {
	l := map[string]string{"name": r.Name}
	if r.Description != "" {
		l["description"] = r.Description
	}
	if r.Instance != nil {
		l["instance"] = *r.Instance
	}
	return l
}

func (t *treeRecords) SaveRole(r *models.Role, members []models.RoleMember, instances []string) error {
	base, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		var n *datastore.Node
		if r.ID == 0 {
			if e.roleNode(r.Name) != nil {
				if strict {
					return records.ErrExists
				}
				n = e.roleNode(r.Name)
				n.Leaves = roleLeaves(r)
			} else {
				n = e.tree.Root.AddEntry(e.tree.Root.S.Child("role"), roleLeaves(r))
			}
		} else {
			old := e.role(r.ID)
			if old == nil {
				if strict {
					return records.ErrNotFound
				}
				return nil
			}
			n = e.roleNode(old.Name)
			if r.Name != old.Name {
				if err := e.tree.Rename(datastore.PathOf(n), []string{r.Name}); err != nil {
					return err
				}
			}
			n.Leaves = roleLeaves(r)
		}
		n.Lists["member"], n.Lists["grant"] = nil, nil
		for _, m := range members {
			u := e.user(m.UserID)
			if u == nil {
				if strict {
					return records.ErrNoSuchUser
				}
				continue
			}
			n.AddEntry(n.S.Child("member"), map[string]string{"user": u.Username, "level": m.Level})
		}
		if r.Instance == nil {
			for _, name := range instances {
				n.AddEntry(n.S.Child("grant"), map[string]string{"instance": name})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if r.ID == 0 {
		if err := t.setID(base, "role", []string{r.Name}, &r.Base); err != nil {
			return err
		}
	}
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return err
	}
	if i, ok := idx.roleByID[r.ID]; ok {
		r.Members, r.Instances = slices.Clone(idx.roles[i].Members), slices.Clone(idx.roles[i].Instances)
	}
	return nil
}

// dropRole removes a role and the mappings that name it.
func (e *accessEnv) dropRole(n *datastore.Node) error {
	name := n.Leaf("name")
	for _, m := range slices.Clone(e.tree.Root.Lists["ldap-role-mapping"]) {
		if m.Leaf("role") == name {
			if err := e.tree.Delete(datastore.PathOf(m)); err != nil {
				return err
			}
		}
	}
	return e.tree.Delete(datastore.PathOf(n))
}

func (t *treeRecords) DeleteRole(id uint) error {
	_, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		old := e.role(id)
		if old == nil {
			if strict {
				return records.ErrNotFound
			}
			return nil
		}
		return e.dropRole(e.roleNode(old.Name))
	})
	return err
}

// DropInstanceRoles removes the roles of the instances not in keep, and the
// grants of the others to them.
func (t *treeRecords) DropInstanceRoles(keep []string) error {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return err
	}
	need := false
	for _, r := range idx.roles {
		if r.Instance != nil && !slices.Contains(keep, *r.Instance) {
			need = true
		}
		if r.Instance == nil {
			for _, in := range r.Instances {
				need = need || !slices.Contains(keep, in)
			}
		}
	}
	if !need {
		return nil
	}
	_, err = t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		for _, n := range slices.Clone(e.tree.Root.Lists["role"]) {
			if in := n.Leaf("instance"); in != "" {
				if !slices.Contains(keep, in) {
					if err := e.dropRole(n); err != nil {
						return err
					}
				}
				continue
			}
			for _, g := range slices.Clone(n.Lists["grant"]) {
				if !slices.Contains(keep, g.Leaf("instance")) {
					if err := e.tree.Delete(datastore.PathOf(g)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	return err
}

// ----- the directory's users -----

// knownServer is the server's name, or "" when no server has it (it was
// deleted since: a user copied from it is no one's).
func (t *treeRecords) knownServer(server string) string {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return ""
	}
	for _, l := range idx.view.LdapServers {
		if l.Name == server {
			return server
		}
	}
	return ""
}

func (t *treeRecords) CopyDirectoryUser(username, server string, d records.DirectoryUser) (*models.User, error) {
	server = t.knownServer(server)
	if u, err := t.UserNamed(username); err == nil {
		if u.PasswordHash != models.LDAPPassword {
			return nil, nil // a local user since: theirs is the local password
		}
		return u, t.UpdateDirectoryUser(u, server, d)
	} else if !errors.Is(err, records.ErrNotFound) {
		return nil, err
	}
	if t.s.isReplica() {
		return nil, nil // users are made on the primary
	}
	u := &models.User{Username: username, PasswordHash: models.LDAPPassword, LdapServer: server, Role: models.RoleNone,
		FullName: d.DisplayName, Email: d.Email, DateFormat: "locale"}
	if err := t.CreateUser(u); err != nil {
		if errors.Is(err, records.ErrExists) { // made meanwhile
			return t.CopyDirectoryUser(username, server, d)
		}
		return nil, err
	}
	return u, t.syncMemberships(u, d.Groups)
}

func (t *treeRecords) UpdateDirectoryUser(u *models.User, server string, d records.DirectoryUser) error {
	server = t.knownServer(server)
	name, email := u.FullName, u.Email
	if d.DisplayName != "" {
		name = d.DisplayName
	}
	if d.Email != "" {
		email = d.Email
	}
	changed := name != u.FullName || email != u.Email || server != u.LdapServer
	u.FullName, u.Email, u.LdapServer = name, email, server
	if t.s.isReplica() {
		return nil // a copy: it authenticates, it doesn't write
	}
	// Nothing written when nothing changed: a login must not bump the
	// candidate (and the replica's ETag) each time.
	if changed {
		if err := t.setUserLeaves(u, map[string]string{"full-name": name, "email": email, "ldap-server": server}); err != nil {
			return err
		}
	}
	return t.syncMemberships(u, d.Groups)
}

// syncMemberships makes the user a member of the roles their groups map to
// (records.PlanMemberships), writing only what differs.
func (t *treeRecords) syncMemberships(u *models.User, groups []string) error {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return err
	}
	mappings := idx.view.LdapRoleMappings
	var have []models.RoleMember
	for _, m := range idx.view.RoleMembers {
		if m.UserID == u.ID {
			have = append(have, m)
		}
	}
	plan := records.PlanMemberships(u.ID, mappings, have, groups)
	if len(plan.Add) == 0 && len(plan.Level) == 0 && len(plan.Remove) == 0 {
		return nil
	}
	_, err = t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		for _, id := range plan.Remove {
			if m := memberNode(e, id); m != nil {
				if err := e.tree.Delete(datastore.PathOf(m)); err != nil {
					return err
				}
			}
		}
		for id, level := range plan.Level {
			if m := memberNode(e, id); m != nil {
				m.Leaves["level"] = level
			}
		}
		for _, m := range plan.Add {
			r, usr := e.role(m.RoleID), e.user(m.UserID)
			if r == nil || usr == nil {
				continue
			}
			rn := e.roleNode(r.Name)
			if rn.Entry("member", []string{usr.Username}) == nil {
				rn.AddEntry(rn.S.Child("member"), map[string]string{"user": usr.Username, "level": m.Level})
			}
		}
		return nil
	})
	return err
}

// memberNode is the membership with the id, nil for none.
func memberNode(e *accessEnv, id uint) *datastore.Node {
	for _, m := range e.v.RoleMembers {
		if m.ID != id {
			continue
		}
		r, u := e.role(m.RoleID), e.user(m.UserID)
		if r == nil || u == nil {
			return nil
		}
		e.names.members[id] = [2]string{r.Name, u.Username}
		if rn := e.roleNode(r.Name); rn != nil {
			return rn.Entry("member", []string{u.Username})
		}
	}
	if rl, ok := e.names.members[id]; ok {
		if rn := e.roleNode(rl[0]); rn != nil {
			return rn.Entry("member", []string{rl[1]})
		}
	}
	return nil
}

// ----- the roles of the virtual firewalls -----

// renamedBothWays are the lists whose entries are renamed in what runs and the
// candidate together (editAccess), never in the candidate alone.
var renamedBothWays = []string{"user", "role", "firewall"}

// FollowChange makes the roles follow a change of the candidate c: an
// instance's own role is made when the candidate gets the instance, and
// renamed with it, in the candidate and in what runs together (so its members
// can be set before the first commit); then the records' own follow-up.
func (t *treeRecords) FollowChange(m *sqlmap.Mapping, c *datastore.Tree) error {
	// What runs and the candidate each have the ids of these entries by
	// path: a rename made to the candidate alone would leave them with two.
	if t.s.bothTrees.Load() == 0 {
		for _, r := range c.Renamed {
			if len(r.Path) == 1 && slices.Contains(renamedBothWays, r.Path[0].Name) {
				return bad("a " + r.Path[0].Name + " is renamed where it is made (the Directory page): it is renamed in what runs and in the candidate together")
			}
		}
	}
	if err := t.s.followInstanceRoles(c); err != nil {
		return err
	}
	return t.Kept.FollowChange(m, c)
}

func (s *Server) followInstanceRoles(c *datastore.Tree) error {
	type rename struct{ old, new string }
	var renames []rename
	for _, r := range c.Renamed {
		if len(r.Path) == 1 && r.Path[0].Name == "instance" {
			renames = append(renames, rename{r.Path[0].Keys[0], r.Keys[0]})
		}
	}
	var instances []string
	for _, in := range c.Root.Lists["instance"] {
		instances = append(instances, in.Leaf("name"))
	}
	apply := func(tree *datastore.Tree) (changed bool, err error) {
		for _, r := range renames {
			if rn := tree.Root.Entry("role", []string{instanceRoleName(r.old)}); rn != nil && rn.Leaf("instance") == r.old {
				if err := tree.Rename(datastore.PathOf(rn), []string{instanceRoleName(r.new)}); err != nil {
					return false, err
				}
				tree.Root.Entry("role", []string{instanceRoleName(r.new)}).Leaves["instance"] = r.new
				changed = true
			}
			for _, rn := range tree.Root.Lists["role"] {
				if g := rn.Entry("grant", []string{r.old}); g != nil {
					if err := tree.Rename(datastore.PathOf(g), []string{r.new}); err != nil {
						return false, err
					}
					changed = true
				}
			}
		}
		for _, name := range instances {
			if tree.Root.Entry("role", []string{instanceRoleName(name)}) == nil {
				tree.Root.AddEntry(tree.Root.S.Child("role"), roleLeaves(&models.Role{
					Name: instanceRoleName(name), Description: "Users of virtual firewall " + name, Instance: &name}))
				changed = true
			}
		}
		return changed, nil
	}
	// What runs first (the candidate's tree is c, which becomes the
	// candidate; its roles are those of the change's own tree).
	if s.isReplica() {
		_, err := apply(c)
		return err
	}
	t := &s.treeState
	ran := false
	if len(renames) > 0 || s.missingInstanceRoles(instances) {
		if _, err := s.commitGlobalsOf(context.Background(), t, func(base *datastore.Tree) error {
			_, err := apply(base)
			return err
		}); err != nil {
			return err
		}
		ran = true
	}
	before := len(c.Renamed)
	_, err := apply(c)
	if ran {
		// What runs has moved the ids of the renamed roles already.
		c.Renamed = c.Renamed[:before]
	}
	return err
}

// missingInstanceRoles tells whether what runs lacks the role of an instance.
func (s *Server) missingInstanceRoles(instances []string) bool {
	idx, err := s.accessIndex(context.Background())
	if err != nil {
		return true
	}
	for _, name := range instances {
		found := false
		for _, r := range idx.roles {
			if r.Instance != nil && *r.Instance == name {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

// ----- firewalls -----

// Firewalls are the firewalls that run, in id order, with the generation last
// handed to each one's agent (runtime, not in the tree).
func (t *treeRecords) Firewalls() ([]models.Firewall, error) {
	idx, err := t.s.accessIndex(context.Background())
	if err != nil {
		return nil, err
	}
	gens, err := t.Kept.Generations()
	if err != nil {
		return nil, err
	}
	out := slices.Clone(idx.firewalls)
	for i := range out {
		out[i].Generation = gens[out[i].ID]
	}
	return out, nil
}

func (t *treeRecords) Firewall(id uint) (*models.Firewall, error) {
	fws, err := t.Firewalls()
	if err != nil {
		return nil, err
	}
	for i := range fws {
		if fws[i].ID == id {
			return &fws[i], nil
		}
	}
	return nil, records.ErrNotFound
}

// firewallLeaves are a firewall's leaves; primary is the name of its HA
// primary.
func firewallLeaves(f *models.Firewall, primary string) map[string]string {
	l := map[string]string{"name": f.Name}
	put := func(k, v string) {
		if v != "" {
			l[k] = v
		}
	}
	put("description", f.Description)
	put("agent-url", f.AgentURL)
	put("agent-token", f.AgentToken)
	put("agent-fingerprint", f.AgentFingerprint)
	put("ha-primary", primary)
	put("ha-secret", f.HASecret)
	if f.HAEpoch != 0 {
		l["ha-epoch"] = strconv.FormatInt(f.HAEpoch, 10)
	}
	put("ha-witness", f.HAWitness)
	put("ha-witness-secret", f.HAWitnessSecret)
	if !f.HAPreempt {
		l["ha-preempt"] = "false"
	}
	put("config-url", f.ConfigURL)
	put("config-fingerprint", f.ConfigFingerprint)
	return l
}

func (t *treeRecords) EnsureFirewall(name string) error {
	// Nothing to make: no write, which a portitor-config whose role is not
	// known yet (an HA pair's, at start) would refuse.
	if fws, err := t.Firewalls(); err == nil && len(fws) > 0 {
		return nil
	}
	_, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		if len(e.tree.Root.Lists["firewall"]) > 0 {
			return nil
		}
		e.tree.Root.AddEntry(e.tree.Root.S.Child("firewall"), map[string]string{"name": name})
		return nil
	})
	return err
}

func (t *treeRecords) SetAgentConnection(id uint, url, token, fingerprint string) error {
	_, err := t.s.editAccess(context.Background(), func(e *accessEnv, strict bool) error {
		f := e.firewall(id)
		if f == nil {
			if strict {
				return records.ErrNotFound
			}
			return nil
		}
		n := e.firewallNode(f.Name)
		for k, v := range map[string]string{"agent-url": url, "agent-token": token, "agent-fingerprint": fingerprint} {
			if v == "" {
				delete(n.Leaves, k)
			} else {
				n.Leaves[k] = v
			}
		}
		return nil
	})
	return err
}

// PromoteFirewalls swaps the pair: prim, the old primary, becomes the
// secondary at the next epoch, sec the primary. One write, to what runs and
// the candidate, made on the replica that is being promoted. Their agent URLs
// stay.
func (t *treeRecords) PromoteFirewalls(sec, prim *models.Firewall) error {
	_, err := t.s.editAccessAs(context.Background(), true, func(e *accessEnv, strict bool) error {
		s, p := e.firewall(sec.ID), e.firewall(prim.ID)
		if s == nil || p == nil {
			if strict {
				return records.ErrNotFound
			}
			return nil
		}
		sn, pn := e.firewallNode(s.Name), e.firewallNode(p.Name)
		witness, witnessSecret := p.HAWitness, p.HAWitnessSecret
		if witness == "" {
			witness = models.HAWitnessLocal
		}
		preempt, hasPreempt := pn.Leaves["ha-preempt"]
		for _, k := range []string{"ha-primary", "ha-secret", "ha-epoch", "ha-witness", "ha-witness-secret", "ha-preempt"} {
			delete(sn.Leaves, k)
			delete(pn.Leaves, k)
		}
		sn.Leaves["ha-witness"] = witness
		if hasPreempt {
			sn.Leaves["ha-preempt"] = preempt
		}
		if witnessSecret != "" {
			sn.Leaves["ha-witness-secret"] = witnessSecret
		}
		pn.Leaves["ha-primary"] = s.Name
		if sec.HASecret != "" {
			pn.Leaves["ha-secret"] = sec.HASecret
		}
		pn.Leaves["ha-epoch"] = strconv.FormatInt(sec.HAEpoch+1, 10)
		pn.Leaves["ha-witness"] = models.HAWitnessLocal
		return nil
	})
	return err
}
