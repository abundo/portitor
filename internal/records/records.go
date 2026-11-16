// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package records is what portitor-config keeps besides the configuration
// tree, and its interface to the tree's own records (users, roles, the
// directory, firewalls), shaped after the three homes of
// dev/design-no-database.md: a method is a domain operation on the tree or a
// JSON file.
//
//   - History (deployments, known NICs): append and query.
//   - Runtime (the commit counter, and later the sessions' and TOTP's
//     counters, generations and the HA epoch): its own methods, never a save
//     of a whole row; an operation that was one conditional update stays one.
//   - Directory data (users, roles, the LDAP directory, firewalls): reads and
//     coarse writes of lists of the tree.
//
// Files implements what is kept in files (Kept: history, counters, ids,
// sessions, generations; store.go); the users, roles, directory and
// firewalls are lists of the configuration tree, which web's treeRecords
// answers on top of Files. The contract tests (records_test.go) run on Files.
package records

import (
	"errors"
	"time"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/models"
)

// ErrNotFound is the answer for a record that does not exist.
var ErrNotFound = errors.New("not found")

// ErrExists is the refusal of a name that is in use.
var ErrExists = errors.New("already exists")

// ErrNoSuchUser is SaveRole's refusal of a member that is no user.
var ErrNoSuchUser = errors.New("no such user")

// Kept is what is kept in files, not in the tree: what Files implements.
type Kept interface {
	History
	Counters
	Ids
	Sessions
	// SetGeneration records the generation last handed to the agent
	// (runtime: never carried by saving the whole firewall; only raised).
	SetGeneration(id uint, generation int64) error
	// Generations are those of every firewall that has one.
	Generations() (map[uint]int64, error)
}

var _ Kept = (*Files)(nil)

// Store is every kind of record, composed of the parts below.
type Store interface {
	History
	Counters
	Firewalls
	Users
	Directory
	Roles
	Ids
	Sessions
}

// History is what happened: deployments and the interfaces seen.
type History interface {
	// RecordDeployment adds a deployment, which gets its ID.
	RecordDeployment(dep *models.Deployment) error
	// UpdateDeployment writes back a deployment's status, message and log.
	UpdateDeployment(dep *models.Deployment) error
	// LatestDeployment is the firewall's newest deployment, whatever its
	// status; nil when it has none.
	LatestDeployment(firewallID uint) (*models.Deployment, error)
	// LiveDeployment is the newest deployment the firewall runs, or runs
	// pending confirmation (status applied, pending or confirmed); a failed
	// or rolled back one left the previous one in place. Nil when none.
	LiveDeployment(firewallID uint) (*models.Deployment, error)
	// RecentDeployments are the newest deployments of all firewalls, newest
	// first.
	RecentDeployments(limit int) ([]models.Deployment, error)
	// LiveCommits are the newest commits some deployment runs, newest first.
	LiveCommits(limit int) ([]int64, error)
	// PruneDeployments forgets the oldest deployments: all but the newest
	// keep (0: no limit), and those made before olderThan (zero: no limit).
	// What each firewall needs is never forgotten: the deployment it runs,
	// the newest settled one (the rollback target of a pending one) and its
	// latest.
	PruneDeployments(keep int, olderThan time.Time) error

	// KnownNICs are the interface names the firewall's agent has reported
	// before; RememberNICs adds names (already known ones are kept).
	KnownNICs(firewallID uint) ([]string, error)
	RememberNICs(firewallID uint, names []string) error
}

// Own is what portitor-config keeps that is not configuration: the commit
// counter, and the certificate it serves HTTPS with (an id of the
// configuration's, until the reference is the tree's).
type Own struct {
	LastCommit       int64
	WebCertificateID *uint
}

// Counters is the commit counter and the settings that are not
// configuration.
type Counters interface {
	Own() (Own, error)
	// SetLastCommit burns a commit number, which is never given twice.
	SetLastCommit(n int64) error
	SetWebCertificate(id *uint) error
}

// Firewalls are the hosts portitor-config deploys to. Reads are coarse (the
// list is small; what an HA pair is, or which one is first, is worked out
// from it by the caller), writes are the operations that are one
// transaction or one runtime column.
type Firewalls interface {
	// Firewalls lists every firewall in id order, the first first.
	Firewalls() ([]models.Firewall, error)
	// Firewall is one by id; ErrNotFound when there is none.
	Firewall(id uint) (*models.Firewall, error)
	// EnsureFirewall adds a firewall with this name if there is none.
	EnsureFirewall(name string) error
	// SetAgentConnection sets how to reach a firewall's agent.
	SetAgentConnection(id uint, url, token, fingerprint string) error
	// SetGeneration records the generation last handed to the agent
	// (runtime: never carried by saving the whole firewall; only raised).
	SetGeneration(id uint, generation int64) error
	// Generations are those of every firewall that has one.
	Generations() (map[uint]int64, error)
	// PromoteFirewalls swaps an HA pair's rows in one transaction: prim, the
	// old primary, becomes the secondary at the next epoch, sec the primary.
	// Their agent URLs stay.
	PromoteFirewalls(sec, prim *models.Firewall) error
}

// Users are the people who log in. A user's configuration (profile, role,
// password hash, directory server, whether two-factor login is required) is
// written by SaveUser; the runtime values (the session counter, the TOTP
// replay step and a setup in progress) have their own methods and are never
// carried by a save of the whole user. The TOTP "each code once" operations
// are single conditional updates, so two requests can't both use one code.
type Users interface {
	// Users lists every user by name.
	Users() ([]models.User, error)
	// User is one by id, UserNamed one by login name; ErrNotFound when
	// there is none.
	User(id uint) (*models.User, error)
	UserNamed(name string) (*models.User, error)
	// CreateUser adds a user, which gets its ID; a name in use is an error.
	CreateUser(u *models.User) error
	// SaveUser writes u's configuration. With revoke it also ends the
	// user's sessions in the same transaction, u.TokenVersion being the new
	// counter afterwards.
	SaveUser(u *models.User, revoke bool) error
	// DeleteUser removes a user and their role memberships.
	DeleteUser(id uint) error

	// BeginTOTP stores a secret being set up (not yet in force).
	BeginTOTP(u *models.User, secret string) error
	// EnableTOTP puts the pending secret in force, with the step of the code
	// that proved it and the hashes of the new recovery codes (a JSON list).
	EnableTOTP(u *models.User, step int64, recoveryHashes string) error
	// SetRecoveryCodes replaces the recovery codes (a JSON list of hashes).
	SetRecoveryCodes(u *models.User, hashes string) error
	// ClearTOTP turns two-factor login off.
	ClearTOTP(u *models.User) error
	// UseTOTPStep accepts a TOTP step if it is newer than the last one
	// accepted; false when it is not (a replay).
	UseTOTPStep(userID uint, step int64) (bool, error)
	// UseRecoveryCode replaces the recovery codes only if they are still
	// current (what the caller read); false when another request used one.
	UseRecoveryCode(userID uint, current, rest string) (bool, error)
}

// Grant is a user's access to an instance, by name, from their roles.
type Grant struct {
	Instance string
	Level    string
}

// DirectoryUser is what the directory has of a user.
type DirectoryUser struct {
	DisplayName, Email string
	Groups             []string
}

// Directory is the LDAP directory's side of the records: the users it let in
// and the roles its groups map to (its servers are configuration, in the tree).
type Directory interface {
	// RoleMappings are the group-to-role mappings, in the order they were
	// made.
	RoleMappings() ([]models.LdapRoleMapping, error)
	// UserGrants are the instances a user has access to through roles.
	UserGrants(userID uint) ([]Grant, error)
	// CopyDirectoryUser adds a user the directory let in, with no global
	// role, and gives them their groups' roles; one of that name already
	// there is updated if it came from the directory, and nil is returned
	// for a local user (theirs is the local password). One transaction.
	CopyDirectoryUser(username, server string, d DirectoryUser) (*models.User, error)
	// UpdateDirectoryUser takes what the directory has of a user: name, email,
	// server and mapped roles. One transaction.
	UpdateDirectoryUser(u *models.User, server string, d DirectoryUser) error
}

// Roles are the groups that grant users access to instances, by name. Each
// instance but the default has its own role (Role.Instance), made and
// removed with the instance (Ids.FollowChange, DropInstanceRoles).
type Roles interface {
	// Roles lists every role with its Members and Instances filled, the
	// instances' own roles first, then by name.
	Roles() ([]models.Role, error)
	// RoleMembers are all the memberships, in the order they were made.
	RoleMembers() ([]models.RoleMember, error)
	// Role is one by id (without its members); ErrNotFound when none.
	Role(id uint) (*models.Role, error)
	// SaveRole creates the role (ID 0) or updates it, and replaces its
	// members and, for a role made by hand, the instances it grants: one
	// transaction. r.Members and r.Instances are those afterwards.
	// ErrNoSuchUser when a member is no user.
	SaveRole(r *models.Role, members []models.RoleMember, instances []string) error
	// DeleteRole removes a role with its members and grants.
	DeleteRole(id uint) error
	// DropInstanceRoles removes the roles and grants of the instances not in
	// keep.
	DropInstanceRoles(keep []string) error
}

// Ids are what ties the records to the configuration tree: the ids kept for
// its entries (rules' connection marks, instances' HA addresses).
type Ids interface {
	sqlmap.Source
	// FollowChange makes the records follow a change of the candidate, all
	// or nothing: a renamed instance's role is renamed, a new instance gets
	// its role, new entries get their ids (and renamed ones keep theirs),
	// and the web certificate is forgotten when its entry is gone.
	FollowChange(m *sqlmap.Mapping, c *datastore.Tree) error
	// Seed makes every file there is (ids, counters, deployments, known
	// interfaces, sessions) now, empty where there is none yet.
	Seed() error
	// UpdateIDs changes the ids kept with fn (sqlmap.IDs.Set), all or
	// nothing: for what is adopted into the tree with the ids it had.
	UpdateIDs(fn func(ids sqlmap.IDs)) error
	// AssignIDs gives the entries of tree that have none their ids (and
	// those renamed keep theirs), as FollowChange does, for a tree that is
	// not the candidate: what runs of the global lists.
	AssignIDs(m *sqlmap.Mapping, tree *datastore.Tree) (sqlmap.Index, error)
	// ExportState is the files of the installation's state that a copy
	// carries, by name: a backup the entries' ids, the replica's copy the
	// deployments and known interfaces too (it needs them to catch up and
	// to take over).
	ExportState(forReplica bool) (map[string][]byte, error)
	// ImportState makes a copy's files (ExportState's) this installation's;
	// a copy without the ids is refused. What a copy does not carry stays as
	// it is.
	ImportState(files map[string][]byte) error
}

// Sessions are the users' runtime values, which are not configuration
// (sessions.json): never in a commit, a backup or a diff.
type Sessions interface {
	// Runtime fills the values into users: the token version, the TOTP step
	// last used, a secret being set up, and their recovery codes without the
	// ones used.
	Runtime(users ...*models.User) error
	// Revoke raises the user's token version, which ends their sessions, and
	// returns the new one. A deleted user's stays: whoever gets the id
	// again starts above it.
	Revoke(userID uint) (int, error)
	// SetTOTPPending stores a secret being set up.
	SetTOTPPending(userID uint, secret string) error
	// EnableTOTPState ends a setup: nothing pending, the step of the code
	// that proved it, and no recovery code used.
	EnableTOTPState(userID uint, step int64) error
	// ClearTOTPState forgets the user's TOTP state.
	ClearTOTPState(userID uint) error
	// UseTOTPStep accepts a step if it is newer than the last accepted;
	// false when it is not (a replay).
	UseTOTPStep(userID uint, step int64) (bool, error)
	// MarkRecoveryCodeUsed marks a recovery code (its hash) used; false when
	// it was already.
	MarkRecoveryCodeUsed(userID uint, hash string) (bool, error)
	// ForgetRecoveryCodes drops the used codes that are not in codes: the
	// user has new ones.
	ForgetRecoveryCodes(userID uint, codes []string) error
}
