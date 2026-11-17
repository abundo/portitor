// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/abundo/portitor/internal/cli"
)

// portalClient is a client logged in to the portal as a user made for it; it
// does not follow redirects.
func portalClient(t *testing.T, p *Portal, base string) *http.Client {
	t.Helper()
	if err := CreatePortalUser(p.store, "admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(base+"/portal/v1/login", "application/json", strings.NewReader(`{"user":"admin","password":"correct horse battery"}`))
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("portal login: %v %v", res, err)
	}
	res.Body.Close()
	return &http.Client{
		Transport:     cookieTransport{res.Cookies()},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type cookieTransport struct{ cookies []*http.Cookie }

func (c cookieTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for _, ck := range c.cookies {
		r.AddCookie(ck)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestPortalConfigInTree(t *testing.T) {
	cfg := &PortalConfig{DataDir: t.TempDir(), Firewalls: []PortalFirewall{{Name: "old", URL: "http://127.0.0.1:1"}}}
	p, err := NewPortal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// manager.yaml's list was taken in once.
	if fws := p.store.Firewalls(); len(fws) != 1 || fws[0].Name != "old" {
		t.Fatalf("imported firewalls: %+v", fws)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	c := portalClient(t, p, srv.URL)
	post := func(method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var b bytes.Buffer
		_, _ = b.ReadFrom(res.Body)
		return res.StatusCode, b.String()
	}
	if code, b := post("POST", "/portal/v1/firewalls", `{"name":"new","url":"http://127.0.0.1:2"}`); code != http.StatusOK {
		t.Fatalf("add: %d %s", code, b)
	}
	if code, _ := post("POST", "/portal/v1/firewalls", `{"name":"new","url":"http://127.0.0.1:2"}`); code != http.StatusConflict {
		t.Errorf("add twice: %d", code)
	}
	if code, _ := post("POST", "/portal/v1/firewalls", `{"name":"bad","url":"https://a:1"}`); code != http.StatusBadRequest {
		t.Errorf("https without fingerprint: %d", code)
	}
	// The proxy table followed the change.
	if _, ok := p.proxyFor("new"); !ok {
		t.Error("no proxy for the new firewall")
	}
	if code, _ := post("DELETE", "/portal/v1/firewalls/old", ""); code != http.StatusOK {
		t.Errorf("delete: %d", code)
	}
	if _, ok := p.proxyFor("old"); ok {
		t.Error("proxy left after delete")
	}
	// The tree is on disk and survives a restart; the password hash is not
	// shown by the API.
	again, err := OpenPortalStore(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if fws := again.Firewalls(); len(fws) != 1 || fws[0].Name != "new" {
		t.Errorf("after restart: %+v", fws)
	}
	if _, b := post("GET", "/portal/v1/config", ""); strings.Contains(b, "$2a$") || !strings.Contains(b, "portitor-portal:firewall") {
		t.Errorf("config: %s", b)
	}
	// A wrong password and a missing cookie.
	if res, _ := http.Post(srv.URL+"/portal/v1/login", "application/json", strings.NewReader(`{"user":"admin","password":"x"}`)); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", res.StatusCode)
	}
	if res, _ := http.Get(srv.URL + "/portal/v1/firewalls"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session: %d", res.StatusCode)
	}
}

// testSSHServer answers `portitor-config portal-info` for password "pw".
func testSSHServer(t *testing.T, info string) (addr, hostKey string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == "pw" {
			return nil, nil
		}
		return nil, context.Canceled
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					ch, creqs, _ := nch.Accept()
					go func() {
						for r := range creqs {
							if r.Type == "exec" {
								_ = r.Reply(true, nil)
								cmd := string(r.Payload[4:])
								if cmd == "portitor-config portal-info" {
									_, _ = ch.Write([]byte(info))
									_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								} else {
									_, _ = ch.Stderr().Write([]byte("unexpected " + cmd))
									_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
								}
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func TestSSHProbe(t *testing.T) {
	info, _ := json.Marshal(PortalInfo{Port: 8444, TLS: true, Fingerprint: strings.Repeat("ab", 32), Version: "1"})
	addr, key := testSSHServer(t, string(info))
	host, port, _ := net.SplitHostPort(addr)
	var n int
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	p := SSHProbe{Host: host, Port: n, User: "root", Password: "pw"}
	// First contact only asks for the host key: no login is tried.
	res, err := RunSSHProbe(context.Background(), p)
	if err != nil || !res.Confirm || res.HostKey != key || res.Info != nil {
		t.Fatalf("first contact: %+v %v", res, err)
	}
	// A different key than the confirmed one is refused.
	bad := p
	bad.HostKey = "SHA256:other"
	if _, err := RunSSHProbe(context.Background(), bad); err == nil {
		t.Error("a host key that differs from the confirmed one was accepted")
	}
	p.HostKey = key
	res, err = RunSSHProbe(context.Background(), p)
	if err != nil || res.Info == nil || res.URL != "https://"+host+":8444" || res.Info.Fingerprint != strings.Repeat("ab", 32) {
		t.Fatalf("probe: %+v %v", res, err)
	}
	p.Password = "wrong"
	if _, err := RunSSHProbe(context.Background(), p); err == nil {
		t.Error("wrong password accepted")
	}
	if configCommand("alice", "portal-info") != "sudo -n -u portitor portitor-config portal-info" {
		t.Error("a user other than root runs it as the service user")
	}
}

// Two processes share the file: a console command's change is seen by the
// daemon's store, and its next edit keeps it.
func TestPortalStoreSharedFile(t *testing.T) {
	dir := t.TempDir()
	daemon, err := OpenPortalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.PutFirewall(PortalFirewall{Name: "a", URL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	cli, err := OpenPortalStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.PutFirewall(PortalFirewall{Name: "b", URL: "http://127.0.0.1:2"}); err != nil {
		t.Fatal(err)
	}
	if err := CreatePortalUser(cli, "bob", "longenoughpass"); err != nil {
		t.Fatal(err)
	}
	if err := daemon.PutFirewall(PortalFirewall{Name: "c", URL: "http://127.0.0.1:3"}); err != nil {
		t.Fatal(err)
	}
	if n := len(daemon.Firewalls()); n != 3 {
		t.Errorf("the daemon lost the console's firewall: %d", n)
	}
	if _, ok := daemon.PasswordHash("bob"); !ok {
		t.Error("the daemon lost the console's user")
	}
}

func TestPortalWitness(t *testing.T) {
	p, err := NewPortal(&PortalConfig{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	w := WitnessPair{Pair: "pair1", Secret: strings.Repeat("s", 40), Hosts: []WitnessHost{
		{Name: "a", URL: "https://192.0.2.1:8443", Fingerprint: strings.Repeat("ab", 32)},
		{Name: "b", URL: "https://192.0.2.2:8443", Fingerprint: strings.Repeat("cd", 32)}}}
	if err := p.store.PutWitness(w.String()); err != nil {
		t.Fatal(err)
	}
	if got := p.store.Witnesses(); len(got) != 1 || got[0] != w.String() {
		t.Fatalf("witnesses: %v", got)
	}
	// The secret is not in the API's view of the tree.
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	c := portalClient(t, p, srv.URL)
	res, _ := c.Get(srv.URL + "/portal/v1/config")
	var b bytes.Buffer
	_, _ = b.ReadFrom(res.Body)
	if strings.Contains(b.String(), w.Secret) || strings.Contains(b.String(), "portitor-witness:") {
		t.Errorf("the witness string is shown: %s", b.String())
	}
	// A change of another entry keeps the secret; deleting the entry removes it.
	if err := p.store.PutFirewall(PortalFirewall{Name: "x", URL: "http://127.0.0.1:1"}); err != nil || len(p.store.Witnesses()) != 1 {
		t.Fatalf("the witness string after another edit: %v %v", err, p.store.Witnesses())
	}
	if err := p.store.DeleteWitness("pair1"); err != nil || len(p.store.Witnesses()) != 0 {
		t.Errorf("delete: %v %v", err, p.store.Witnesses())
	}
}

// The portal's own cookie never reaches a firewall.
func TestPortalCookieNotForwarded(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Cookie") }))
	defer backend.Close()
	p, err := NewPortal(&PortalConfig{DataDir: t.TempDir(), Firewalls: []PortalFirewall{{Name: "fw1", URL: backend.URL}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	c := portalClient(t, p, srv.URL)
	req, _ := http.NewRequest("GET", srv.URL+"/fw/fw1/x", nil)
	req.AddCookie(&http.Cookie{Name: "fw_session", Value: "keep"})
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got != "fw_session=keep" {
		t.Errorf("the firewall got the cookies %q", got)
	}
}

// The portal's configuration is edited as a firewall's: through the CLI's
// candidate, and a commit makes the daemon's proxies follow.
func TestPortalCLI(t *testing.T) {
	p, err := NewPortal(&PortalConfig{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	run := func(script string) error {
		out.Reset()
		return cli.RunScript(context.Background(), p.store.CLIEnv("console"), strings.NewReader(script), &out)
	}
	if err := run("configure\nset firewall lab url http://127.0.0.1:9\n"); err != nil {
		t.Fatal(err)
	}
	// Not committed: the portal does not serve it yet.
	if _, ok := p.proxyFor("lab"); ok {
		t.Error("served before the commit")
	}
	if err := run("configure\nset firewall lab url http://127.0.0.1:9\nset firewall bad url https://x:1\ncommit\n"); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("a firewall without its fingerprint committed: %v", err)
	}
	if err := run("configure\ndelete firewall bad\ncommit\n"); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.proxyFor("lab"); !ok {
		t.Error("not served after the commit")
	}
	if err := run("configure\ncommit confirmed 30\n"); err == nil {
		t.Error("commit confirmed has nothing to roll back to")
	}
}

// A firewall request without the portal's session is marked as the portal's
// 401, which a framed GUI hands to the portal's page.
func TestPortalExpiredMarker(t *testing.T) {
	p, err := NewPortal(&PortalConfig{DataDir: t.TempDir(), Firewalls: []PortalFirewall{{Name: "fw1", URL: "http://127.0.0.1:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/fw/fw1/api/me")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get(portalLoginHeader) != "login" {
		t.Errorf("%d %v", res.StatusCode, res.Header)
	}
}
