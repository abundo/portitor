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
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/confview"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ldapauth"
	"github.com/abundo/portitor/internal/records"
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
func authenticateUser(ctx context.Context, s *Server, username, password string) (*models.User, error) {
	u, err := s.rec.UserNamed(username)
	switch {
	case errors.Is(err, records.ErrNotFound):
		return authenticateNewDirectoryUser(ctx, s, username, password)
	case err != nil:
		return nil, err
	case u.PasswordHash == models.LDAPPassword:
		return authenticateDirectoryUser(ctx, s, u, password)
	case bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil:
		return u, nil
	}
	return nil, nil
}

func authenticateNewDirectoryUser(ctx context.Context, s *Server, username, password string) (*models.User, error) {
	server, info, err := directoryLogin(ctx, s, username, password)
	if err != nil || info == nil {
		if info == nil {
			// The time a bcrypt check takes, as for a local user.
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		}
		return nil, err
	}
	u, err := s.rec.CopyDirectoryUser(username, server, directoryUserOf(info))
	if err != nil {
		return nil, err
	}
	slog.Info("directory: user copied in", "user", username, "server", server)
	return u, nil
}

func authenticateDirectoryUser(ctx context.Context, s *Server, u *models.User, password string) (*models.User, error) {
	server, info, err := directoryLogin(ctx, s, u.Username, password)
	if err != nil || info == nil {
		return nil, err
	}
	if err := s.rec.UpdateDirectoryUser(u, server, directoryUserOf(info)); err != nil {
		return nil, err
	}
	return u, nil
}

// directoryUserOf is what the directory said of a user, for the records.
func directoryUserOf(info *ldapauth.UserInfo) records.DirectoryUser {
	return records.DirectoryUser{DisplayName: info.DisplayName, Email: info.Email, Groups: info.Groups}
}

// directoryLogin checks a password at the enabled servers in order: one
// that is down or doesn't accept it is passed over. It returns the server
// that accepted it and what it has of the user; no info when none did.
func directoryLogin(ctx context.Context, s *Server, username, password string) (string, *ldapauth.UserInfo, error) {
	if password == "" || !fwconfig.ValidOpenVPNUser(username) {
		return "", nil, nil
	}
	servers, err := s.enabledDirectoryServers(ctx)
	if err != nil {
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
func checkPassword(ctx context.Context, s *Server, u *models.User, password string) bool {
	if u.PasswordHash == models.LDAPPassword {
		_, info, err := directoryLogin(ctx, s, u.Username, password)
		return err == nil && info != nil
	}
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}

// ----- directory servers -----

func prepareLdapServer(v *confview.View, l, old *models.LdapServer) error {
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
	for _, o := range v.LdapServers {
		if o.Name == l.Name && o.ID != l.ID {
			return bad(fmt.Sprintf("there is already a directory server %s", l.Name))
		}
	}
	if old == nil {
		// Last in the login order.
		l.Position = len(v.LdapServers) + 1
	} else {
		l.Position = old.Position
	}
	return nil
}

func presentLdapServer(l *models.LdapServer) {
	l.Position++ // the API counts from 1; the tree's order from 0
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
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	if len(req.IDs) != len(v.LdapServers) {
		return dbError(c, bad("list every directory server once"))
	}
	seen := map[uint]bool{}
	for _, id := range req.IDs {
		if seen[id] || directoryServer(v, id) == nil {
			if seen[id] {
				return dbError(c, bad("list every directory server once"))
			}
			return dbError(c, bad(fmt.Sprintf("no directory server %d", id)))
		}
		seen[id] = true
	}
	r := s.directoryServers()
	if ok, err := r.write(c, func(work *datastore.Tree, w *rowWriter) error {
		// In order: each moved last, the first one ends up first.
		for _, id := range req.IDs {
			n := w.add.Node("ldap_servers", int64(id))
			if err := work.Move(datastore.PathOf(n), "last", nil); err != nil {
				return err
			}
		}
		return nil
	}); !ok {
		return err
	}
	return c.NoContent(http.StatusNoContent)
}

// directoryServer is the server of the rows with the id, nil for none.
func directoryServer(v *confview.View, id uint) *models.LdapServer {
	for i := range v.LdapServers {
		if v.LdapServers[i].ID == id {
			return &v.LdapServers[i]
		}
	}
	return nil
}

// directoryServers is the directory servers' CRUD (a global list of the
// tree, committed on write).
func (s *Server) directoryServers() *treeResource[models.LdapServer, *models.LdapServer] {
	return &treeResource[models.LdapServer, *models.LdapServer]{
		s: s, list: "ldap-server", table: "ldap_servers",
		rows:    func(v *confview.View) []models.LdapServer { return v.LdapServers },
		named:   func(l *models.LdapServer) string { return l.Name },
		prepare: prepareLdapServer, present: presentLdapServer,
	}
}

// enabledDirectoryServers are the servers a login is tried at, in order,
// as committed.
func (s *Server) enabledDirectoryServers(ctx context.Context) ([]models.LdapServer, error) {
	idx, err := s.accessIndex(ctx)
	if err != nil {
		return nil, err
	}
	var out []models.LdapServer
	for _, l := range idx.view.LdapServers {
		if l.Enabled {
			out = append(out, l)
		}
	}
	return out, nil
}

// handleTestLdapServer connects to a server as the form has it (the stored
// bind password when the form leaves it empty) and binds and searches.
func (s *Server) handleTestLdapServer(c *echo.Context) error {
	var l models.LdapServer
	if err := c.Bind(&l); err != nil {
		return errJSON(c, http.StatusBadRequest, "invalid request")
	}
	if l.ID != 0 {
		if v, err := s.view(c.Request().Context()); err == nil {
			if old := directoryServer(v, l.ID); old != nil {
				l.BindPassword = old.BindPassword
			}
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
	v, err := s.view(c.Request().Context())
	if err != nil {
		return err
	}
	l := directoryServer(v, id)
	if l == nil {
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

func prepareLdapRoleMapping(v *confview.View, m, _ *models.LdapRoleMapping) error {
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
	if !slices.ContainsFunc(v.Roles, func(r models.Role) bool { return r.ID == m.RoleID }) {
		return bad("role: no such role")
	}
	for _, o := range v.LdapRoleMappings {
		if o.ID != m.ID && o.RoleID == m.RoleID && strings.EqualFold(o.GroupDn, m.GroupDn) {
			return bad("that group is mapped to that role already")
		}
	}
	return nil
}

// roleMappings is the directory's group mappings' CRUD (a global list of the
// tree, committed on write).
func (s *Server) roleMappings() *treeResource[models.LdapRoleMapping, *models.LdapRoleMapping] {
	return &treeResource[models.LdapRoleMapping, *models.LdapRoleMapping]{
		s: s, list: "ldap-role-mapping", table: "ldap_role_mappings",
		rows:    func(v *confview.View) []models.LdapRoleMapping { return v.LdapRoleMappings },
		named:   func(m *models.LdapRoleMapping) string { return strconv.FormatUint(uint64(m.ID), 10) },
		prepare: prepareLdapRoleMapping,
	}
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
	_, err := s.rec.CopyDirectoryUser(l.User, l.Server, records.DirectoryUser{DisplayName: l.DisplayName, Email: l.Email, Groups: slices.Clone(l.Groups)})
	return err
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
