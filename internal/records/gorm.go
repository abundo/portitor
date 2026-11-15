// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package records

import (
	"encoding/json"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/models"
)

// GORM is the Store on the SQLite database, with the entries' ids and the
// installation's counters in files next to it (files.go).
type GORM struct {
	db    *gorm.DB
	files fileState
}

var _ Store = (*GORM)(nil)

// NewGORM is the Store on db, keeping its files in dir ("": in memory).
func NewGORM(db *gorm.DB, dir string) *GORM {
	g := &GORM{db: db}
	g.files.dir = dir
	return g
}

func (g *GORM) Own() (Own, error) {
	defer g.files.begin(false)()
	if err := g.files.loadState(g.db); err != nil {
		return Own{}, err
	}
	if err := g.files.loadDeployments(g.db); err != nil {
		return Own{}, err
	}
	// The counter is the highest number given anywhere it is kept.
	last := max(g.files.st.LastCommit, g.files.lastDeployedCommit())
	for _, d := range g.files.deps {
		last = max(last, d.CommitID)
	}
	return Own{LastCommit: last, WebCertificateID: g.files.st.WebCertificateID}, nil
}

func (g *GORM) SetLastCommit(n int64) error {
	defer g.files.begin(true)()
	if err := g.files.loadState(g.db); err != nil {
		return err
	}
	st := g.files.st
	st.LastCommit = n
	return g.files.setState(st)
}

func (g *GORM) SetWebCertificate(id *uint) error {
	defer g.files.begin(true)()
	if err := g.files.loadState(g.db); err != nil {
		return err
	}
	st := g.files.st
	st.WebCertificateID = id
	return g.files.setState(st)
}

func (g *GORM) Firewalls() ([]models.Firewall, error) {
	var fws []models.Firewall
	err := g.db.Order("id").Find(&fws).Error
	return fws, err
}

func (g *GORM) Firewall(id uint) (*models.Firewall, error) {
	var fw models.Firewall
	if err := g.db.First(&fw, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &fw, nil
}

func (g *GORM) EnsureFirewall(name string) error {
	return g.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.Firewall{}).Count(&n).Error; err != nil || n > 0 {
			return err
		}
		return tx.Create(&models.Firewall{Name: name}).Error
	})
}

func (g *GORM) SetAgentConnection(id uint, url, token, fingerprint string) error {
	return g.db.Model(&models.Firewall{}).Where("id = ?", id).Updates(map[string]any{
		"agent_url": url, "agent_token": token, "agent_fingerprint": fingerprint,
	}).Error
}

// SetGeneration raises the generation handed to the firewall's agent; it is
// the file's, never lowered (a restore knows nothing of it).
func (g *GORM) SetGeneration(id uint, generation int64) error {
	defer g.files.begin(true)()
	if err := g.files.loadSessions(g.db); err != nil {
		return err
	}
	if generation <= g.files.gens[id] {
		return nil
	}
	g.files.gens[id] = generation
	return g.files.writeSessions()
}

func (g *GORM) Generations() (map[uint]int64, error) {
	defer g.files.begin(false)()
	if err := g.files.loadSessions(g.db); err != nil {
		return nil, err
	}
	out := make(map[uint]int64, len(g.files.gens))
	for id, gen := range g.files.gens {
		out[id] = gen
	}
	return out, nil
}

func (g *GORM) PromoteFirewalls(sec, prim *models.Firewall) error {
	return g.db.Transaction(func(tx *gorm.DB) error {
		witness, witnessSecret := prim.HAWitness, prim.HAWitnessSecret
		if witness == "" {
			witness = models.HAWitnessLocal
		}
		if err := tx.Model(&models.Firewall{}).Where("id = ?", sec.ID).Updates(map[string]any{
			"ha_primary_id": nil, "ha_secret": "", "ha_epoch": 0,
			"ha_witness": witness, "ha_witness_secret": witnessSecret,
		}).Error; err != nil {
			return err
		}
		return tx.Model(&models.Firewall{}).Where("id = ?", prim.ID).Updates(map[string]any{
			"ha_primary_id": sec.ID, "ha_secret": sec.HASecret, "ha_epoch": sec.HAEpoch + 1,
			"ha_witness": models.HAWitnessLocal, "ha_witness_secret": "",
		}).Error
	})
}

// Users.

func (g *GORM) Users() ([]models.User, error) {
	users := []models.User{}
	if err := g.db.Order("username").Find(&users).Error; err != nil {
		return nil, err
	}
	ptrs := make([]*models.User, len(users))
	for i := range users {
		ptrs[i] = &users[i]
	}
	return users, g.withRuntime(ptrs...)
}

func (g *GORM) User(id uint) (*models.User, error) {
	var u models.User
	if err := g.db.First(&u, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, g.withRuntime(&u)
}

func (g *GORM) UserNamed(name string) (*models.User, error) {
	var u models.User
	if err := g.db.Where("username = ?", name).First(&u).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &u, g.withRuntime(&u)
}

func (g *GORM) CreateUser(u *models.User) error { return g.db.Create(u).Error }

// runtimeUserColumns are the user's columns that a save of its
// configuration leaves alone (their values are in sessions.json).
var runtimeUserColumns = []string{"token_version", "totp_last_step", "totp_pending"}

// revoke ends the user's sessions: the version raised first, so a failure
// after it is a session ended that need not have been.
func (g *GORM) revoke(u *models.User) error {
	r, _, err := g.changeSession(u.ID, func(r *sessionRec) bool { r.TokenVersion++; return true })
	u.TokenVersion = r.TokenVersion
	return err
}

func (g *GORM) SaveUser(u *models.User, revoke bool) error {
	if revoke {
		if err := g.revoke(u); err != nil {
			return err
		}
	}
	return g.db.Omit(runtimeUserColumns...).Save(u).Error
}

func (g *GORM) DeleteUser(id uint) error {
	// The sessions end, and the id's version stays above them.
	if err := g.revoke(&models.User{Base: models.Base{ID: id}}); err != nil {
		return err
	}
	return g.db.Delete(&models.User{}, id).Error
}

func (g *GORM) BeginTOTP(u *models.User, secret string) error {
	if _, _, err := g.changeSession(u.ID, func(r *sessionRec) bool { r.TOTPPending = secret; return true }); err != nil {
		return err
	}
	u.TOTPPending = secret
	return nil
}

func (g *GORM) EnableTOTP(u *models.User, step int64, recoveryHashes string) error {
	secret := u.TOTPPending
	if err := g.db.Model(u).Updates(map[string]any{"totp_secret": secret, "recovery_codes": recoveryHashes}).Error; err != nil {
		return err
	}
	if _, _, err := g.changeSession(u.ID, func(r *sessionRec) bool { r.TOTPPending, r.TOTPLastStep = "", step; return true }); err != nil {
		return err
	}
	u.TOTPPending, u.TOTPLastStep = "", step
	return nil
}

func (g *GORM) SetRecoveryCodes(u *models.User, hashes string) error {
	return g.db.Model(u).Update("recovery_codes", hashes).Error
}

func (g *GORM) ClearTOTP(u *models.User) error {
	if err := g.db.Model(u).Updates(map[string]any{"totp_secret": "", "recovery_codes": ""}).Error; err != nil {
		return err
	}
	if _, _, err := g.changeSession(u.ID, func(r *sessionRec) bool { r.TOTPPending, r.TOTPLastStep = "", 0; return true }); err != nil {
		return err
	}
	u.TOTPPending, u.TOTPLastStep = "", 0
	return nil
}

func (g *GORM) UseTOTPStep(userID uint, step int64) (bool, error) {
	_, ok, err := g.changeSession(userID, func(r *sessionRec) bool {
		if step <= r.TOTPLastStep {
			return false
		}
		r.TOTPLastStep = step
		return true
	})
	return ok, err
}

func (g *GORM) UseRecoveryCode(userID uint, current, rest string) (bool, error) {
	res := g.db.Model(&models.User{}).Where("id = ? AND recovery_codes = ?", userID, current).
		Update("recovery_codes", rest)
	return res.RowsAffected == 1, res.Error
}

// Directory.

func (g *GORM) RoleMappings() ([]models.LdapRoleMapping, error) {
	var out []models.LdapRoleMapping
	return out, g.db.Order("id").Find(&out).Error
}

func (g *GORM) RoleMembers() ([]models.RoleMember, error) {
	var out []models.RoleMember
	return out, g.db.Order("id").Find(&out).Error
}

func (g *GORM) UserGrants(userID uint) ([]Grant, error) {
	var rows []Grant
	err := g.db.Raw(`
		SELECT r.instance AS instance, m.level AS level
		  FROM role_members m JOIN roles r ON r.id = m.role_id
		 WHERE m.user_id = ? AND r.instance IS NOT NULL
		UNION ALL
		SELECT ri.instance, m.level
		  FROM role_members m JOIN role_instances ri ON ri.role_id = m.role_id
		 WHERE m.user_id = ?`, userID, userID).Scan(&rows).Error
	return rows, err
}

func (g *GORM) CopyDirectoryUser(username, server string, d DirectoryUser) (*models.User, error) {
	var out *models.User
	err := g.db.Transaction(func(tx *gorm.DB) error {
		var u models.User
		err := tx.Where("username = ?", username).First(&u).Error
		switch {
		case err == nil && u.PasswordHash != models.LDAPPassword:
			return nil // a local user since: theirs is the local password
		case err == nil:
			out = &u
			return updateDirectoryUser(tx, &u, server, d)
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return err
		}
		u = models.User{Username: username, PasswordHash: models.LDAPPassword, LdapServer: server, Role: models.RoleNone,
			FullName: d.DisplayName, Email: d.Email}
		if err := tx.Create(&u).Error; err != nil {
			return err
		}
		out = &u
		return syncMemberships(tx, &u, d.Groups)
	})
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := g.withRuntime(out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (g *GORM) UpdateDirectoryUser(u *models.User, server string, d DirectoryUser) error {
	return g.db.Transaction(func(tx *gorm.DB) error { return updateDirectoryUser(tx, u, server, d) })
}

func updateDirectoryUser(tx *gorm.DB, u *models.User, server string, d DirectoryUser) error {
	if d.DisplayName != "" {
		u.FullName = d.DisplayName
	}
	if d.Email != "" {
		u.Email = d.Email
	}
	u.LdapServer = server
	if err := tx.Model(u).Updates(map[string]any{"full_name": u.FullName, "email": u.Email, "ldap_server": server}).Error; err != nil {
		return err
	}
	return syncMemberships(tx, u, d.Groups)
}

func syncMemberships(tx *gorm.DB, u *models.User, groups []string) error {
	var mappings []models.LdapRoleMapping
	if err := tx.Find(&mappings).Error; err != nil {
		return err
	}
	var have []models.RoleMember
	if err := tx.Where("user_id = ?", u.ID).Find(&have).Error; err != nil {
		return err
	}
	plan := PlanMemberships(u.ID, mappings, have, groups)
	for _, id := range plan.Remove {
		if err := tx.Delete(&models.RoleMember{}, id).Error; err != nil {
			return err
		}
	}
	for id, level := range plan.Level {
		if err := tx.Model(&models.RoleMember{}).Where("id = ?", id).Update("level", level).Error; err != nil {
			return err
		}
	}
	for i := range plan.Add {
		if err := tx.Create(&plan.Add[i]).Error; err != nil {
			return err
		}
	}
	return nil
}

// Roles.

func (g *GORM) Roles() ([]models.Role, error) {
	roles := []models.Role{}
	if err := g.db.Order("instance IS NULL, name").Find(&roles).Error; err != nil {
		return nil, err
	}
	var members []models.RoleMember
	if err := g.db.Order("id").Find(&members).Error; err != nil {
		return nil, err
	}
	var grants []models.RoleInstance
	if err := g.db.Order("instance").Find(&grants).Error; err != nil {
		return nil, err
	}
	byRole := map[uint][]models.RoleMember{}
	for _, m := range members {
		byRole[m.RoleID] = append(byRole[m.RoleID], m)
	}
	instances := map[uint][]string{}
	for _, gr := range grants {
		instances[gr.RoleID] = append(instances[gr.RoleID], gr.Instance)
	}
	for i := range roles {
		r := &roles[i]
		r.Members = byRole[r.ID]
		if r.Members == nil {
			r.Members = []models.RoleMember{}
		}
		switch {
		case r.Instance != nil:
			r.Instances = []string{*r.Instance}
		case instances[r.ID] != nil:
			r.Instances = instances[r.ID]
		default:
			r.Instances = []string{}
		}
	}
	return roles, nil
}

func (g *GORM) Role(id uint) (*models.Role, error) {
	var r models.Role
	if err := g.db.First(&r, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

func (g *GORM) SaveRole(r *models.Role, members []models.RoleMember, instances []string) error {
	return g.db.Transaction(func(tx *gorm.DB) error {
		if r.ID == 0 {
			if err := tx.Create(r).Error; err != nil {
				return err
			}
		} else if err := tx.Save(r).Error; err != nil {
			return err
		}
		if err := tx.Where("role_id = ?", r.ID).Delete(&models.RoleMember{}).Error; err != nil {
			return err
		}
		r.Members = []models.RoleMember{}
		for _, m := range members {
			rm := models.RoleMember{RoleID: r.ID, UserID: m.UserID, Level: m.Level}
			if err := tx.Create(&rm).Error; err != nil {
				if strings.Contains(err.Error(), "FOREIGN KEY constraint") {
					return ErrNoSuchUser
				}
				return err
			}
			r.Members = append(r.Members, rm)
		}
		if r.Instance != nil {
			r.Instances = []string{*r.Instance}
			return nil
		}
		if err := tx.Where("role_id = ?", r.ID).Delete(&models.RoleInstance{}).Error; err != nil {
			return err
		}
		r.Instances = []string{}
		for _, name := range instances {
			if err := tx.Create(&models.RoleInstance{RoleID: r.ID, Instance: name}).Error; err != nil {
				return err
			}
			r.Instances = append(r.Instances, name)
		}
		return nil
	})
}

func (g *GORM) DeleteRole(id uint) error { return g.db.Delete(&models.Role{}, id).Error }

func (g *GORM) DropInstanceRoles(keep []string) error {
	return g.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("instance IS NOT NULL AND instance NOT IN ?", keep).Delete(&models.Role{}).Error; err != nil {
			return err
		}
		return tx.Where("instance NOT IN ?", keep).Delete(&models.RoleInstance{}).Error
	})
}

// Ids.

func (g *GORM) IDs() (sqlmap.IDs, error) {
	defer g.files.begin(false)()
	if err := g.files.loadIDs(g.db); err != nil {
		return sqlmap.IDs{}, err
	}
	return g.files.ids, nil
}

func (g *GORM) AssignIDs(m *sqlmap.Mapping, tree *datastore.Tree) (sqlmap.Index, error) {
	defer g.files.begin(true)()
	if err := g.files.loadIDs(g.db); err != nil {
		return nil, err
	}
	next, idx := m.PlanIDs(g.files.ids, tree)
	if !next.Equal(g.files.ids) {
		if err := g.files.setIDs(next); err != nil {
			return nil, err
		}
	}
	return idx, nil
}

func (g *GORM) Seed() error {
	defer g.files.begin(true)()
	f := &g.files
	for _, load := range []func(*gorm.DB) error{f.loadIDs, f.loadState, f.loadDeployments, f.loadNICs, f.loadSessions} {
		if err := load(g.db); err != nil {
			return err
		}
	}
	return nil
}

func (g *GORM) UpdateIDs(fn func(ids sqlmap.IDs)) error {
	defer g.files.begin(true)()
	if err := g.files.loadIDs(g.db); err != nil {
		return err
	}
	next := g.files.ids.Clone()
	fn(next)
	return g.files.setIDs(next)
}

func (g *GORM) ExportState(forReplica bool) (map[string][]byte, error) {
	defer g.files.begin(false)()
	if err := g.files.loadIDs(g.db); err != nil {
		return nil, err
	}
	b, err := json.Marshal(g.files.ids)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{entryIDsFile: b}
	if !forReplica {
		return out, nil
	}
	if err := g.files.loadDeployments(g.db); err != nil {
		return nil, err
	}
	if out[deploymentsFile], err = g.files.encodeDeployments(); err != nil {
		return nil, err
	}
	if err := g.files.loadNICs(g.db); err != nil {
		return nil, err
	}
	if out[knownNICsFile], err = json.Marshal(g.files.nics); err != nil {
		return nil, err
	}
	// The sessions are valid on both hosts of a pair.
	if err := g.files.loadSessions(g.db); err != nil {
		return nil, err
	}
	if out[sessionsFile], err = json.Marshal(sessionsJSON{Version: 1, Users: g.files.sess, Generations: g.files.gens}); err != nil {
		return nil, err
	}
	return out, nil
}

func (g *GORM) ImportState(files map[string][]byte) error {
	defer g.files.begin(true)()
	if b, ok := files[entryIDsFile]; ok {
		var ids sqlmap.IDs
		if err := json.Unmarshal(b, &ids); err != nil {
			return err
		}
		if err := g.files.setIDs(ids); err != nil {
			return err
		}
	} else if err := g.files.seedIDs(g.db); err != nil {
		// A copy from before the ids were a file has them in its table.
		return err
	}
	if b, ok := files[deploymentsFile]; ok {
		g.files.deps, g.files.depNext = nil, 1
		g.files.parseDeployments(b)
		g.files.depsLoaded = true
		if err := g.files.rewriteDeployments(); err != nil {
			return err
		}
	}
	if b, ok := files[sessionsFile]; ok {
		if err := g.files.loadSessions(g.db); err != nil {
			return err
		}
		if err := g.files.mergeSessions(b); err != nil {
			return err
		}
	}
	if b, ok := files[knownNICsFile]; ok {
		var nics map[uint][]string
		if err := json.Unmarshal(b, &nics); err != nil {
			return err
		}
		g.files.nics, g.files.nicsLoaded = nics, true
		if err := g.files.writeNICs(); err != nil {
			return err
		}
	}
	return nil
}

func (g *GORM) ExternalNames(table string) (map[int64]string, error) {
	var rows []struct {
		ID   int64
		Name string
	}
	if err := g.db.Table(table).Select("id, name").Find(&rows).Error; err != nil {
		return nil, err
	}
	names := make(map[int64]string, len(rows))
	for _, r := range rows {
		names[r.ID] = r.Name
	}
	return names, nil
}

// instanceRolePrefix starts the name of each instance's role; a role made
// by hand can't use it.
const instanceRolePrefix = "vf-"

func (g *GORM) FollowChange(m *sqlmap.Mapping, c *datastore.Tree) error {
	defer g.files.begin(true)()
	if err := g.files.loadIDs(g.db); err != nil {
		return err
	}
	next, idx := m.PlanIDs(g.files.ids, c)
	if !next.Equal(g.files.ids) {
		if err := g.files.setIDs(next); err != nil {
			return err
		}
	}
	return g.forgetWebCertificate(idx)
}

// forgetWebCertificate forgets the certificate chosen for portitor-config
// when the configuration no longer has it, under files.mu.
func (g *GORM) forgetWebCertificate(idx sqlmap.Index) error {
	if err := g.files.loadState(g.db); err != nil {
		return err
	}
	cert := g.files.st.WebCertificateID
	if cert == nil {
		return nil
	}
	for n, id := range idx {
		if n.S.Name == "certificate" && uint(id) == *cert {
			return nil
		}
	}
	st := g.files.st
	st.WebCertificateID = nil
	return g.files.setState(st)
}
