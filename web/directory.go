// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ldapauth"
	"github.com/abundo/portitor/models"
)

// The directory (Admin → Directory): the users and roles, and the OpenLDAP
// and Active Directory servers every login tries for a user the firewall
// doesn't have. A user the directory lets in is copied to the users
// (models.LDAPPassword, users.ldap_server) and from then on checked at the
// servers again; the roles that directory groups map to
// (ldap_role_mappings) follow their groups at each login. The GUI's login
// takes this path here (authenticateUser), OpenVPN's the same path in the
// agent, which reports the users it let in for runDirectorySync to copy.

// directoryAuth is ldapauth.Authenticate, replaceable in tests.
var directoryAuth = ldapauth.Authenticate

// authenticateUser checks a user name and password:
//
//  1. a local user: their bcrypt hash;
//  2. a user copied from the directory: at the directory's servers, and
//     their name, email and mapped roles are updated;
//  3. no such user: at the directory's servers, and on success the user is
//     copied in, with no global role.
//
// It returns the user, nil for a wrong user name or password (or no
// server that accepts it), and an error only for the database.
func authenticateUser(ctx context.Context, db *gorm.DB, username, password string) (*models.User, error) {
	var u models.User
	err := db.Where("username = ?", username).First(&u).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return authenticateNewDirectoryUser(ctx, db, username, password)
	case err != nil:
		return nil, err
	case u.PasswordHash == models.LDAPPassword:
		return authenticateDirectoryUser(ctx, db, &u, password)
	case bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil:
		return &u, nil
	}
	return nil, nil
}

func authenticateNewDirectoryUser(ctx context.Context, db *gorm.DB, username, password string) (*models.User, error) {
	server, info, err := directoryLogin(ctx, db, username, password)
	if err != nil || info == nil {
		if info == nil {
			// The time a bcrypt check takes, as for a local user.
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		}
		return nil, err
	}
	var u *models.User
	err = db.Transaction(func(tx *gorm.DB) error {
		var err error
		u, err = copyDirectoryUser(tx, username, server, info)
		return err
	})
	if err != nil {
		return nil, err
	}
	slog.Info("directory: user copied in", "user", username, "server", server)
	return u, nil
}

func authenticateDirectoryUser(ctx context.Context, db *gorm.DB, u *models.User, password string) (*models.User, error) {
	server, info, err := directoryLogin(ctx, db, u.Username, password)
	if err != nil || info == nil {
		return nil, err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		return updateDirectoryUser(tx, u, server, info)
	})
	if err != nil {
		return nil, err
	}
	return u, nil
}

// copyDirectoryUser adds a user the directory let in, with no global role,
// and gives them their groups' roles. A user of that name already there
// is updated instead, if it came from the directory.
func copyDirectoryUser(tx *gorm.DB, username, server string, info *ldapauth.UserInfo) (*models.User, error) {
	var u models.User
	err := tx.Where("username = ?", username).First(&u).Error
	switch {
	case err == nil && u.PasswordHash != models.LDAPPassword:
		return nil, nil // a local user since: theirs is the local password
	case err == nil:
		return &u, updateDirectoryUser(tx, &u, server, info)
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return nil, err
	}
	u = models.User{Username: username, PasswordHash: models.LDAPPassword, LdapServer: server, Role: models.RoleNone,
		FullName: info.DisplayName, Email: info.Email}
	if err := tx.Create(&u).Error; err != nil {
		return nil, err
	}
	return &u, syncDirectoryRoles(tx, &u, info.Groups)
}

// updateDirectoryUser takes what the directory has of a user: name, email,
// server and mapped roles.
func updateDirectoryUser(tx *gorm.DB, u *models.User, server string, info *ldapauth.UserInfo) error {
	if info.DisplayName != "" {
		u.FullName = info.DisplayName
	}
	if info.Email != "" {
		u.Email = info.Email
	}
	u.LdapServer = server
	if err := tx.Model(u).Updates(map[string]any{"full_name": u.FullName, "email": u.Email, "ldap_server": server}).Error; err != nil {
		return err
	}
	return syncDirectoryRoles(tx, u, info.Groups)
}

// syncDirectoryRoles makes a directory user a member of the roles their
// groups map to, at the highest level mapped, and no member of the other
// roles any group maps to. Roles no group maps to are left as an admin set
// them.
func syncDirectoryRoles(tx *gorm.DB, u *models.User, groups []string) error {
	var mappings []models.LdapRoleMapping
	if err := tx.Find(&mappings).Error; err != nil {
		return err
	}
	mapped := map[uint]bool{}
	want := map[uint]string{}
	for _, m := range mappings {
		mapped[m.RoleID] = true
		if ldapauth.InGroups(groups, []string{m.GroupDn}) && want[m.RoleID] != models.RoleAdmin {
			want[m.RoleID] = m.Level
		}
	}
	var have []models.RoleMember
	if err := tx.Where("user_id = ?", u.ID).Find(&have).Error; err != nil {
		return err
	}
	for _, m := range have {
		if !mapped[m.RoleID] {
			continue
		}
		level, ok := want[m.RoleID]
		switch {
		case !ok:
			if err := tx.Delete(&models.RoleMember{}, m.ID).Error; err != nil {
				return err
			}
		case level != m.Level:
			if err := tx.Model(&models.RoleMember{}).Where("id = ?", m.ID).Update("level", level).Error; err != nil {
				return err
			}
		}
		delete(want, m.RoleID)
	}
	for roleID, level := range want {
		if err := tx.Create(&models.RoleMember{RoleID: roleID, UserID: u.ID, Level: level}).Error; err != nil {
			return err
		}
	}
	return nil
}

// directoryLogin checks a password at the enabled servers in order: one
// that is down or doesn't accept it is passed over. It returns the server
// that accepted it and what it has of the user; no info when none did.
func directoryLogin(ctx context.Context, db *gorm.DB, username, password string) (string, *ldapauth.UserInfo, error) {
	if password == "" || !fwconfig.ValidOpenVPNUser(username) {
		return "", nil, nil
	}
	var servers []models.LdapServer
	if err := db.Where("enabled").Order("position, id").Find(&servers).Error; err != nil {
		return "", nil, err
	}
	for i := range servers {
		l := &servers[i]
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		ok, info, err := directoryAuth(lctx, l.Config(), username, password)
		cancel()
		switch {
		case err != nil:
			slog.Warn("directory: server failed", "server", l.Name, "user", username, "err", err)
		case ok:
			return l.Name, info, nil
		}
	}
	return "", nil, nil
}

// checkPassword checks a logged-in user's password (to change their
// two-factor login): their hash, or the directory's.
func checkPassword(ctx context.Context, db *gorm.DB, u *models.User, password string) bool {
	if u.PasswordHash == models.LDAPPassword {
		_, info, err := directoryLogin(ctx, db, u.Username, password)
		return err == nil && info != nil
	}
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}

// ----- directory servers -----

func prepareLdapServer(tx *gorm.DB, l, old *models.LdapServer) error {
	l.Name, l.Host = strings.TrimSpace(l.Name), strings.TrimSpace(l.Host)
	l.BindDn, l.BaseDn = strings.TrimSpace(l.BindDn), strings.TrimSpace(l.BaseDn)
	l.UserFilter = strings.TrimSpace(l.UserFilter)
	if l.ServerType == "" {
		l.ServerType = ldapauth.TypeGeneric
	}
	if l.TlsMode == "" {
		l.TlsMode = ldapauth.TLSNone
	}
	if l.Port == 0 {
		l.Port = ldapauth.DefaultPort(l.TlsMode)
	}
	if l.UserFilter != "" {
		if err := ldapauth.CheckFilter(l.UserFilter); err != nil {
			return bad(err.Error())
		}
	}
	l.CaCert = strings.TrimSpace(l.CaCert)
	if l.CaCert != "" {
		l.CaCert += "\n"
	}
	switch {
	case l.ClearBindPassword:
		l.BindPassword = ""
	case l.NewBindPassword != "":
		l.BindPassword = l.NewBindPassword
	}
	l.NewBindPassword, l.ClearBindPassword = "", false
	if l.BindDn == "" {
		l.BindPassword = ""
	}
	if l.BindDn != "" && l.BindPassword == "" {
		return bad("bind password: required with a bind DN")
	}
	if errs := fwconfig.CheckLDAPServer(l.Server()); len(errs) > 0 {
		return bad(fmt.Sprintf("directory server %s: %s", l.Name, strings.Join(errs, "; ")))
	}
	var n int64
	if err := tx.Model(&models.LdapServer{}).Where("name = ? AND id <> ?", l.Name, l.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("there is already a directory server %s", l.Name))
	}
	if old == nil {
		// Last in the login order.
		var last int
		tx.Model(&models.LdapServer{}).Select("COALESCE(MAX(position), 0)").Scan(&last)
		l.Position = last + 1
	} else {
		l.Position = old.Position
	}
	return nil
}

func presentLdapServer(l *models.LdapServer) {
	l.HasBindPassword = l.BindPassword != ""
	l.NewBindPassword, l.ClearBindPassword = "", false
}

// handleReorderLdapServers sets the login order: the servers' ids in it.
func (s *Server) handleReorderLdapServers(c *echo.Context) error {
	var req struct {
		IDs []uint `json:"ids"`
	}
	if err := c.Bind(&req); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.LdapServer{}).Count(&n).Error; err != nil {
			return err
		}
		if int(n) != len(req.IDs) {
			return bad("list every directory server once")
		}
		for i, id := range req.IDs {
			res := tx.Model(&models.LdapServer{}).Where("id = ?", id).Update("position", i+1)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected != 1 {
				return bad(fmt.Sprintf("no directory server %d", id))
			}
		}
		return nil
	})
	if err != nil {
		return dbError(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}

// handleTestLdapServer connects to a server as the form has it (the stored
// bind password when the form leaves it empty) and binds and searches.
func (s *Server) handleTestLdapServer(c *echo.Context) error {
	var l models.LdapServer
	if err := c.Bind(&l); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if l.ID != 0 {
		var old models.LdapServer
		if err := s.db.First(&old, l.ID).Error; err == nil {
			l.BindPassword = old.BindPassword
		}
	}
	if l.NewBindPassword != "" {
		l.BindPassword = l.NewBindPassword
	}
	if l.Port == 0 {
		l.Port = ldapauth.DefaultPort(l.TlsMode)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 15*time.Second)
	defer cancel()
	if err := ldapauth.TestConnection(ctx, l.Config()); err != nil {
		return c.JSON(http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}

// handleBrowseLdapServer lists the children of ?dn= (the base DN) at a
// server, to pick a group for a role.
func (s *Server) handleBrowseLdapServer(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var l models.LdapServer
	if err := s.db.First(&l, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 15*time.Second)
	defer cancel()
	entries, err := ldapauth.Browse(ctx, l.Config(), c.QueryParam("dn"))
	if err != nil {
		return errJSON(c, http.StatusBadGateway, err.Error())
	}
	return c.JSON(http.StatusOK, entries)
}

func prepareLdapRoleMapping(tx *gorm.DB, m, _ *models.LdapRoleMapping) error {
	m.GroupDn = strings.TrimSpace(m.GroupDn)
	if m.GroupDn == "" || len(m.GroupDn) > 1024 || strings.ContainsFunc(m.GroupDn, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return bad("group DN: one line of at most 1024 characters")
	}
	if m.Level == "" {
		m.Level = models.RoleViewer
	}
	if !validLevel(m.Level) {
		return bad("level must be admin or viewer")
	}
	if err := tx.First(&models.Role{}, m.RoleID).Error; err != nil {
		return bad("role: no such role")
	}
	var n int64
	if err := tx.Model(&models.LdapRoleMapping{}).Where("lower(group_dn) = lower(?) AND role_id = ? AND id <> ?", m.GroupDn, m.RoleID, m.ID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad("that group is mapped to that role already")
	}
	return nil
}

// ----- OpenVPN's directory logins -----

// directorySync is when runDirectorySync asks the agents.
const directorySync = 30 * time.Second

// runDirectorySync copies in the users the directory let in to OpenVPN on
// the agents (agentapi.DirectoryLogin), and updates the copied ones' roles,
// until ctx is done. A replica leaves it to the primary.
func (s *Server) runDirectorySync(ctx context.Context) {
	after := map[uint]int64{}
	for sleepCtx(ctx, directorySync) {
		if s.isReplica() {
			continue
		}
		fws, err := s.firewalls()
		if err != nil {
			continue
		}
		for _, fw := range fws {
			s.syncDirectoryLogins(ctx, &fw, after)
		}
	}
}

// syncDirectoryLogins copies one firewall's directory logins since its
// cursor in after.
func (s *Server) syncDirectoryLogins(ctx context.Context, fw *models.Firewall, after map[uint]int64) {
	a, err := s.newAgent(fw)
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := a.DirectoryLogins(cctx, after[fw.ID])
	if err != nil {
		return
	}
	for _, l := range res.Logins {
		after[fw.ID] = max(after[fw.ID], l.ID)
		if err := s.copyDirectoryLogin(l); err != nil {
			slog.Warn("directory: copying an OpenVPN login", "user", l.User, "err", err)
		}
	}
}

func (s *Server) copyDirectoryLogin(l agentapi.DirectoryLogin) error {
	if !fwconfig.ValidOpenVPNUser(l.User) {
		return nil
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		info := &ldapauth.UserInfo{DN: l.DN, Email: l.Email, DisplayName: l.DisplayName, Groups: slices.Clone(l.Groups)}
		_, err := copyDirectoryUser(tx, l.User, l.Server, info)
		return err
	})
}

// sleepCtx sleeps d or until ctx is done; false when it is.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
