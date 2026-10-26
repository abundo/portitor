// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ldapauth is the search-and-bind flow that checks a user's
// password at an LDAP or Active Directory server and reads what a local
// copy of the user needs (name, email, groups), and a browser of the
// server's tree for the Directory page. portitor-config uses it for GUI
// logins, the agent for OpenVPN's (fwconfig.Directory). It knows nothing
// of the database: callers hand it a Config.
package ldapauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config is one server's connection and search settings.
type Config struct {
	Host string
	Port int
	// TLSMode is "none", "starttls" or "ldaps".
	TLSMode       string
	SkipTLSVerify bool
	// CACert (PEM) verifies the server's certificate; empty: the system's
	// CAs.
	CACert string
	// ServerType is "ad" or "generic" (OpenLDAP and the like); it picks
	// the defaults.
	ServerType string
	// BindDN and BindPassword are the search identity; both empty is an
	// anonymous bind.
	BindDN       string
	BindPassword string
	BaseDN       string
	// UserFilter finds the user: %s is the escaped user name, e.g.
	// "(sAMAccountName=%s)" or "(uid=%s)".
	UserFilter      string
	AttrEmail       string
	AttrDisplayName string
	// AttrGroups holds the user's group DNs on its entry: memberOf (AD,
	// OpenLDAP with the memberof overlay).
	AttrGroups string
	// Dial opens the TCP connection (from an instance's namespace, for
	// the agent); nil dials from here.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server types and TLS modes.
const (
	TypeGeneric  = "generic"
	TypeAD       = "ad"
	TLSNone      = "none"
	TLSStartTLS  = "starttls"
	TLSLDAPS     = "ldaps"
	timeout      = 10 * time.Second
	dialTimeout  = 5 * time.Second
	defaultGroup = "memberOf"
)

// ServerTypes and TLSModes are the values a server may have.
var (
	ServerTypes = []string{TypeGeneric, TypeAD}
	TLSModes    = []string{TLSNone, TLSStartTLS, TLSLDAPS}
)

// DefaultUserFilter is a server type's user filter.
func DefaultUserFilter(serverType string) string {
	if serverType == TypeAD {
		return "(sAMAccountName=%s)"
	}
	return "(uid=%s)"
}

// DefaultPort is a TLS mode's port.
func DefaultPort(tlsMode string) int {
	if tlsMode == TLSLDAPS {
		return 636
	}
	return 389
}

// WithDefaults fills in what is left empty.
func (c Config) WithDefaults() Config {
	if c.ServerType == "" {
		c.ServerType = TypeGeneric
	}
	if c.TLSMode == "" {
		c.TLSMode = TLSNone
	}
	if c.Port == 0 {
		c.Port = DefaultPort(c.TLSMode)
	}
	if c.UserFilter == "" {
		c.UserFilter = DefaultUserFilter(c.ServerType)
	}
	if c.AttrEmail == "" {
		c.AttrEmail = "mail"
	}
	if c.AttrDisplayName == "" {
		c.AttrDisplayName = "displayName"
	}
	if c.AttrGroups == "" {
		c.AttrGroups = defaultGroup
	}
	return c
}

// UserInfo is what a successful login yields for the local copy of the
// user.
type UserInfo struct {
	DN          string
	Email       string
	DisplayName string
	// Groups are the group DNs of the entry's AttrGroups.
	Groups []string
}

// CheckFilter checks a user filter: in parentheses, with one %s and no
// other % verb.
func CheckFilter(f string) error {
	if !strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")") || strings.Count(f, "%s") != 1 || strings.Count(f, "%") != 1 {
		return errors.New("the user filter must be in parentheses and hold %s once")
	}
	if _, err := ldap.CompileFilter(strings.Replace(f, "%s", "x", 1)); err != nil {
		return fmt.Errorf("user filter: %w", err)
	}
	return nil
}

func (c Config) addr() string {
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(c.Host), "ldaps://"), "ldap://"), "/")
	return net.JoinHostPort(host, strconv.Itoa(c.Port))
}

func (c Config) tlsConfig() (*tls.Config, error) {
	host, _, _ := net.SplitHostPort(c.addr())
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.SkipTLSVerify}
	if c.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(c.CACert)) {
			return nil, errors.New("ldap: invalid CA certificate")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// connect dials the server and, for ldaps or starttls, wraps or upgrades
// the connection. Callers own Close.
func connect(ctx context.Context, cfg Config) (*ldap.Conn, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, errors.New("ldap: no host")
	}
	tc, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	dial := cfg.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	c, err := dial(dctx, "tcp", cfg.addr())
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %s: %w", cfg.addr(), err)
	}
	if cfg.TLSMode == TLSLDAPS {
		t := tls.Client(c, tc)
		if err := t.HandshakeContext(dctx); err != nil {
			c.Close()
			return nil, fmt.Errorf("ldap: tls %s: %w", cfg.addr(), err)
		}
		c = t
	}
	conn := ldap.NewConn(c, cfg.TLSMode == TLSLDAPS)
	conn.Start()
	conn.SetTimeout(timeout)
	if cfg.TLSMode == TLSStartTLS {
		if err := conn.StartTLS(tc); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap: starttls %s: %w", cfg.addr(), err)
		}
	}
	return conn, nil
}

// bindService binds as the search identity: anonymously without a bind
// DN. A bind DN with an empty password would be an unauthenticated bind,
// which some servers accept without a check; go-ldap refuses it.
func bindService(conn *ldap.Conn, cfg Config) error {
	if strings.TrimSpace(cfg.BindDN) == "" {
		if err := conn.UnauthenticatedBind(""); err != nil {
			return fmt.Errorf("ldap: anonymous bind: %w", err)
		}
		return nil
	}
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return fmt.Errorf("ldap: bind as %s: %w", cfg.BindDN, err)
	}
	return nil
}

// TestConnection connects, binds as the search identity and searches the
// base DN, for the Directory page's Test button.
func TestConnection(ctx context.Context, cfg Config) error {
	cfg = cfg.WithDefaults()
	conn, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := bindService(conn, cfg); err != nil {
		return err
	}
	req := ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"dn"}, nil)
	if _, err := conn.Search(req); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return fmt.Errorf("ldap: the base DN: %w", err)
	}
	return nil
}

// Authenticate finds the user with the search identity and binds as the
// entry found with password, on a second connection.
//
//   - (true, info, nil): the password is right.
//   - (false, nil, nil): no such user, or a wrong password.
//   - (false, nil, err): the server or its settings failed (dial, the
//     search identity's bind, the search, a filter that finds more than one
//     entry): the caller tries the next server.
func Authenticate(ctx context.Context, cfg Config, username, password string) (bool, *UserInfo, error) {
	if password == "" {
		return false, nil, nil
	}
	cfg = cfg.WithDefaults()
	conn, err := connect(ctx, cfg)
	if err != nil {
		return false, nil, err
	}
	defer conn.Close()
	if err := bindService(conn, cfg); err != nil {
		return false, nil, err
	}
	filter := strings.Replace(cfg.UserFilter, "%s", ldap.EscapeFilter(username), 1)
	attrs := []string{"dn", cfg.AttrEmail, cfg.AttrDisplayName, cfg.AttrGroups}
	// Two, so a filter that finds several is told apart from one that
	// finds one.
	res, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false, filter, attrs, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return false, nil, fmt.Errorf("ldap: user search: %w", err)
	}
	switch {
	case res == nil || len(res.Entries) == 0:
		return false, nil, nil
	case len(res.Entries) > 1:
		return false, nil, fmt.Errorf("ldap: the user filter %q finds more than one entry", filter)
	}
	entry := res.Entries[0]

	userConn, err := connect(ctx, cfg)
	if err != nil {
		return false, nil, err
	}
	defer userConn.Close()
	if err := userConn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) || ldap.IsErrorWithCode(err, ldap.ErrorEmptyPassword) {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("ldap: bind as the user: %w", err)
	}
	// AD may answer with another case of an attribute's name.
	return true, &UserInfo{
		DN:          entry.DN,
		Email:       entry.GetEqualFoldAttributeValue(cfg.AttrEmail),
		DisplayName: entry.GetEqualFoldAttributeValue(cfg.AttrDisplayName),
		Groups:      entry.GetEqualFoldAttributeValues(cfg.AttrGroups),
	}, nil
}

// NormalizeDN lowercases and trims a DN, to compare group DNs.
func NormalizeDN(dn string) string { return strings.ToLower(strings.TrimSpace(dn)) }

// InGroups says whether any of groups is one of want (DNs, compared
// normalized).
func InGroups(groups, want []string) bool {
	set := map[string]bool{}
	for _, g := range want {
		set[NormalizeDN(g)] = true
	}
	for _, g := range groups {
		if set[NormalizeDN(g)] {
			return true
		}
	}
	return false
}

// Entry is one child in the server's tree.
type Entry struct {
	DN  string `json:"dn"`
	RDN string `json:"rdn"`
	// Kind is "person", "group", "container" or "other".
	Kind string `json:"kind"`
}

var (
	groupClasses     = map[string]bool{"group": true, "groupofnames": true, "groupofuniquenames": true, "posixgroup": true}
	personClasses    = map[string]bool{"inetorgperson": true, "posixaccount": true, "user": true, "person": true}
	containerClasses = map[string]bool{"organizationalunit": true, "container": true, "organization": true, "domain": true,
		"dcobject": true, "country": true, "locality": true, "builtindomain": true}
)

// EntryKind classifies objectClass values: a group before a person
// before a container.
func EntryKind(classes []string) string {
	for _, m := range []struct {
		set  map[string]bool
		kind string
	}{{groupClasses, "group"}, {personClasses, "person"}, {containerClasses, "container"}} {
		for _, oc := range classes {
			if m.set[strings.ToLower(oc)] {
				return m.kind
			}
		}
	}
	return "other"
}

func rdnValue(dn string) string {
	p, err := ldap.ParseDN(dn)
	if err != nil || len(p.RDNs) == 0 || len(p.RDNs[0].Attributes) == 0 {
		return dn
	}
	return p.RDNs[0].Attributes[0].Value
}

// Browse lists the children of dn (the base DN when empty), as the search
// identity, so a group to map to a role can be picked from the tree.
func Browse(ctx context.Context, cfg Config, dn string) ([]Entry, error) {
	cfg = cfg.WithDefaults()
	conn, err := connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := bindService(conn, cfg); err != nil {
		return nil, err
	}
	base := strings.TrimSpace(dn)
	if base == "" {
		base = cfg.BaseDN
	}
	res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 1000, 0, false,
		"(objectClass=*)", []string{"objectClass"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, fmt.Errorf("ldap: browse %q: %w", base, err)
	}
	out := []Entry{}
	if res != nil {
		for _, e := range res.Entries {
			out = append(out, Entry{DN: e.DN, RDN: rdnValue(e.DN), Kind: EntryKind(e.GetEqualFoldAttributeValues("objectClass"))})
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].RDN) < strings.ToLower(out[j].RDN) })
	return out, nil
}
