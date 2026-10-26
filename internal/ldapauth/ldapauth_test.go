// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package ldapauth

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// fakeEntry is an entry of fakeServer's directory.
type fakeEntry struct {
	dn, password string
	attrs        map[string][]string
}

// fakeServer answers binds (simple) and searches by equality filters on
// its entries, enough for Authenticate and Browse.
type fakeServer struct {
	entries []fakeEntry
	// anonymous lets an anonymous bind search.
	anonymous bool
}

func (f *fakeServer) start(t *testing.T) Config {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return Config{Host: "127.0.0.1", Port: p, BindDN: "cn=svc,dc=example,dc=com", BindPassword: "svcpass", BaseDN: "dc=example,dc=com"}
}

func (f *fakeServer) serve(c net.Conn) {
	defer c.Close()
	bound := ""
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id := p.Children[0].Value.(int64)
		op := p.Children[1]
		reply := func(tag ber.Tag, children ...*ber.Packet) {
			env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
			r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
			for _, ch := range children {
				r.AppendChild(ch)
			}
			env.AppendChild(r)
			_, _ = c.Write(env.Bytes())
		}
		result := func(tag ber.Tag, code int64) {
			reply(tag, ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""),
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""),
				ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
		}
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			name := op.Children[1].Value.(string)
			pw := op.Children[2].Data.String()
			code := int64(ldap.LDAPResultInvalidCredentials)
			if name == "" && pw == "" && f.anonymous {
				code, bound = ldap.LDAPResultSuccess, ""
			}
			if name == "cn=svc,dc=example,dc=com" && pw == "svcpass" {
				code, bound = ldap.LDAPResultSuccess, name
			}
			for _, e := range f.entries {
				if strings.EqualFold(e.dn, name) && e.password != "" && e.password == pw {
					code, bound = ldap.LDAPResultSuccess, name
				}
			}
			result(ldap.ApplicationBindResponse, code)
		case ldap.ApplicationSearchRequest:
			if bound == "" && !f.anonymous {
				result(ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights)
				continue
			}
			base := strings.ToLower(op.Children[0].Value.(string))
			scope := op.Children[1].Value.(int64)
			filter, _ := ldap.DecompileFilter(op.Children[6])
			for _, e := range f.entries {
				dn := strings.ToLower(e.dn)
				parent := dn[strings.Index(dn, ",")+1:]
				in := (scope == ldap.ScopeWholeSubtree && strings.HasSuffix(dn, base)) ||
					(scope == ldap.ScopeSingleLevel && parent == base) || (scope == ldap.ScopeBaseObject && dn == base)
				if !in || !matches(e, filter) {
					continue
				}
				attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				for k, vs := range e.attrs {
					a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, ""))
					set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
					for _, v := range vs {
						set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
					}
					a.AppendChild(set)
					attrs.AppendChild(a)
				}
				reply(ldap.ApplicationSearchResultEntry, ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, ""), attrs)
			}
			result(ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess)
		case ldap.ApplicationUnbindRequest:
			return
		default:
			result(op.Tag+1, ldap.LDAPResultUnwillingToPerform)
		}
	}
}

// matches takes "(objectClass=*)" and "(attr=value)" filters.
func matches(e fakeEntry, filter string) bool {
	if filter == "(objectClass=*)" {
		return true
	}
	attr, value, ok := strings.Cut(strings.Trim(filter, "()"), "=")
	if !ok {
		return false
	}
	for k, vs := range e.attrs {
		if strings.EqualFold(k, attr) {
			for _, v := range vs {
				if strings.EqualFold(v, value) {
					return true
				}
			}
		}
	}
	return false
}

func directory() *fakeServer {
	return &fakeServer{entries: []fakeEntry{
		{dn: "ou=people,dc=example,dc=com", attrs: map[string][]string{"objectClass": {"organizationalUnit"}}},
		{dn: "ou=groups,dc=example,dc=com", attrs: map[string][]string{"objectClass": {"organizationalUnit"}}},
		{dn: "uid=alice,ou=people,dc=example,dc=com", password: "alicepass", attrs: map[string][]string{
			"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "mail": {"alice@example.com"}, "displayName": {"Alice A"},
			"memberOf": {"cn=vpn,ou=groups,dc=example,dc=com"},
		}},
		{dn: "uid=twin,ou=people,dc=example,dc=com", password: "x", attrs: map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"twin"}}},
		{dn: "uid=twin2,ou=people,dc=example,dc=com", password: "x", attrs: map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"twin"}}},
		{dn: "cn=vpn,ou=groups,dc=example,dc=com", attrs: map[string][]string{"objectClass": {"groupOfNames"}}},
	}}
}

func TestAuthenticate(t *testing.T) {
	cfg := directory().start(t)
	ctx := context.Background()
	ok, info, err := Authenticate(ctx, cfg, "alice", "alicepass")
	if err != nil || !ok || info.DN != "uid=alice,ou=people,dc=example,dc=com" || info.Email != "alice@example.com" ||
		info.DisplayName != "Alice A" || !InGroups(info.Groups, []string{"CN=VPN,OU=Groups,DC=example,DC=com"}) {
		t.Fatalf("alice: %v %+v %v", ok, info, err)
	}
	for _, c := range []struct{ user, pass string }{{"alice", "wrong"}, {"nobody", "x"}, {"alice", ""}} {
		if ok, _, err := Authenticate(ctx, cfg, c.user, c.pass); ok || err != nil {
			t.Errorf("%s/%s: %v %v", c.user, c.pass, ok, err)
		}
	}
	// A filter that finds two is the server's settings' fault.
	if _, _, err := Authenticate(ctx, cfg, "twin", "x"); err == nil {
		t.Error("ambiguous filter: no error")
	}
	// A wrong service password, an unreachable server: errors.
	bad := cfg
	bad.BindPassword = "nope"
	if _, _, err := Authenticate(ctx, bad, "alice", "alicepass"); err == nil {
		t.Error("wrong bind password: no error")
	}
	if err := TestConnection(ctx, bad); err == nil {
		t.Error("test with a wrong bind password passed")
	}
	if err := TestConnection(ctx, cfg); err != nil {
		t.Errorf("test: %v", err)
	}
	down := cfg
	down.Port = 1
	if _, _, err := Authenticate(ctx, down, "alice", "alicepass"); err == nil {
		t.Error("unreachable: no error")
	}
	// A filter's user name is escaped.
	if ok, _, _ := Authenticate(ctx, cfg, "*", "alicepass"); ok {
		t.Error("wildcard user name let in")
	}
}

func TestAnonymousAndBrowse(t *testing.T) {
	f := directory()
	f.anonymous = true
	cfg := f.start(t)
	cfg.BindDN, cfg.BindPassword = "", ""
	ctx := context.Background()
	if ok, _, err := Authenticate(ctx, cfg, "alice", "alicepass"); !ok || err != nil {
		t.Errorf("anonymous search: %v %v", ok, err)
	}
	got, err := Browse(ctx, cfg, "")
	if err != nil || len(got) != 2 || got[0].RDN != "groups" || got[0].Kind != "container" {
		t.Fatalf("browse: %+v %v", got, err)
	}
	got, _ = Browse(ctx, cfg, "ou=groups,dc=example,dc=com")
	if len(got) != 1 || got[0].Kind != "group" {
		t.Errorf("groups: %+v", got)
	}
}

func TestCheckFilter(t *testing.T) {
	for f, ok := range map[string]bool{"(uid=%s)": true, "(&(objectClass=user)(sAMAccountName=%s))": true,
		"uid=%s": false, "(uid=bob)": false, "(uid=%s%d)": false, "(uid=%s)(cn=%s)": false, "((uid=%s)": false} {
		if (CheckFilter(f) == nil) != ok {
			t.Errorf("%s: %v", f, CheckFilter(f))
		}
	}
}
