// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/ldapauth"
)

// fakeOpenVPN is OpenVPN's side of the management socket: it sends
// notifications and records the commands, answering them.
type fakeOpenVPN struct {
	t     *testing.T
	ln    net.Listener
	conn  net.Conn
	cmds  chan string
	write chan string
}

func newFakeOpenVPN(t *testing.T) (*fakeOpenVPN, string) {
	sock := filepath.Join(t.TempDir(), "udp.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOpenVPN{t: t, ln: ln, cmds: make(chan string, 16), write: make(chan string, 16)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		f.conn = c
		fmt.Fprint(c, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n")
		go func() {
			for s := range f.write {
				fmt.Fprint(c, s)
			}
		}()
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			cmd := sc.Text()
			switch {
			case cmd == "status 3":
				f.write <- "TITLE\tOpenVPN 2.6\nTIME\tx\t1\n" +
					"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\n" +
					"CLIENT_LIST\talice\t192.0.2.10:51000\t10.8.0.2\tfd00:8::2\t1200\t3400\t2026-10-26 10:00:00\t1793008800\talice\t7\t0\tAES-256-GCM\n" +
					"END\n"
			default:
				f.write <- "SUCCESS: done\n"
			}
			f.cmds <- cmd
		}
	}()
	return f, sock
}

func (f *fakeOpenVPN) connect(kind string, cid int, user, pass string) {
	f.write <- fmt.Sprintf(">CLIENT:%s,%d,1\n>CLIENT:ENV,untrusted_ip=192.0.2.10\n>CLIENT:ENV,username=%s\n>CLIENT:ENV,password=%s\n>CLIENT:ENV,END\n", kind, cid, user, pass)
}

func (f *fakeOpenVPN) next() string {
	f.t.Helper()
	select {
	case c := <-f.cmds:
		return c
	case <-time.After(5 * time.Second):
		f.t.Fatal("no command")
		return ""
	}
}

func TestOpenVPNManager(t *testing.T) {
	f, sock := newFakeOpenVPN(t)
	m := newOpenVPNManager(false, &DryRunner{})
	m.failDelay = 0
	m.ldapAuth = func(_ context.Context, l fwconfig.LDAPServer, user, pass string) (bool, *ldapauth.UserInfo, error) {
		groups := map[string][]string{"bob": {"CN=VPN,CN=Users,DC=example,DC=com"}, "dave": {"CN=VPN,CN=Users,DC=example,DC=com"}, "erin": nil}
		g, ok := groups[user]
		if !ok || pass != user+"pass" {
			return false, nil, nil
		}
		return true, &ldapauth.UserInfo{DN: "CN=" + user + ",DC=example,DC=com", Groups: g}, nil
	}
	doc := fwconfig.SampleDocument()
	cfg := *doc.Instances[0].Interfaces[5].OpenVPN
	item := openvpnItem{instance: "main", iface: "ovpn0", device: "ovpn0", unit: "openvpn-server@portitor-udp.service", socket: sock,
		certDir: t.TempDir(), cfg: cfg, dir: doc.Directory.Servers}
	m.Reconcile([]openvpnItem{item})
	defer m.Stop()

	// The sample requires a role: alice is a member, bob a directory user
	// in its group, carol not a member; dave and erin are only in the
	// directory, dave in the group.
	for _, c := range []struct {
		kind       string
		cid        int
		user, pass string
		want       string
	}{
		{"CONNECT", 1, "alice", "alicepass", "client-auth-nt 1 1"},
		{"CONNECT", 2, "alice", "wrong", `client-deny 2 1 "login refused"`},
		{"CONNECT", 3, "bob", "bobpass", "client-auth-nt 3 1"},
		{"CONNECT", 4, "bob", "nope", `client-deny 4 1 "login refused"`},
		{"CONNECT", 5, "carol", "carolpass", `client-deny 5 1 "login refused"`},
		{"CONNECT", 6, "dave", "davepass", "client-auth-nt 6 1"},
		{"CONNECT", 7, "erin", "erinpass", `client-deny 7 1 "login refused"`},
		{"CONNECT", 8, "eve", "x", `client-deny 8 1 "login refused"`},
		{"CONNECT", 10, "alice", "", `client-deny 10 1 "login refused"`},
		// A renegotiation of a client let in needs no password.
		{"REAUTH", 1, "alice", "", "client-auth-nt 1 1"},
		{"REAUTH", 9, "alice", "", `client-deny 9 1 "login refused"`},
	} {
		f.connect(c.kind, c.cid, c.user, c.pass)
		if got := f.next(); got != c.want {
			t.Errorf("%s %d %s: %q, want %q", c.kind, c.cid, c.user, got, c.want)
		}
	}
	// The users the firewall doesn't have that the directory let in are
	// reported to be copied, also the one the role refused.
	var reported []string
	for _, l := range m.logins.After(0) {
		reported = append(reported, l.User+"@"+l.Server)
	}
	if strings.Join(reported, " ") != "dave@ad erin@ad" {
		t.Errorf("reported %v", reported)
	}

	st := m.Status(context.Background())
	if len(st.Servers) != 1 || !st.Servers[0].Connected || len(st.Servers[0].Clients) != 1 {
		t.Fatalf("status %+v", st)
	}
	if c := st.Servers[0].Clients[0]; c.User != "alice" || c.Address6 != "fd00:8::2" || c.RxBytes != 1200 || c.ID != 7 || c.Since.Year() != 2026 {
		t.Errorf("client %+v", c)
	}
	f.next() // status 3

	// alice is no longer a user: her session ends; bob (directory) stays.
	item.cfg.Users = nil
	m.Reconcile([]openvpnItem{item})
	if got := f.next(); got != "client-kill 1" {
		t.Errorf("kill: %q", got)
	}
	select {
	case c := <-f.cmds:
		t.Errorf("unexpected %q", c)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestParseOpenVPNStatusUndefUser(t *testing.T) {
	got := parseOpenVPNStatus([]string{
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tUsername",
		"CLIENT_LIST\tcarol\t[AF_INET6]2001:db8::5:1194\tUNDEF",
	})
	if len(got) != 1 || got[0].User != "carol" || !strings.Contains(got[0].RealAddress, "2001:db8::5") {
		t.Errorf("%+v", got)
	}
}

func TestClientCA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vpn.example.com"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"vpn.example.com"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ca, err := clientCA(chain)
	if err != nil || ca.CommonName != "vpn.example.com" || ca.CA != string(chain) {
		t.Errorf("self-signed: %v %+v", err, ca)
	}
	if _, err := clientCA([]byte("junk")); err == nil {
		t.Error("junk accepted")
	}
}
