// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abundo/portitor/internal/datastore"
)

// sshHost is a fake firewall host over SSH: password "pw", and run answers
// its commands (standard input given), with an error as exit status 1.
func sshHost(t *testing.T, run func(cmd string, stdin []byte) (string, error)) (port int, hostKey string) {
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
							if r.Type != "exec" {
								continue
							}
							_ = r.Reply(true, nil)
							cmd := string(r.Payload[4:])
							var in []byte
							if strings.Contains(cmd, "add-secondary") {
								in, _ = io.ReadAll(ch)
							}
							out, err := run(cmd, in)
							status := byte(0)
							if err != nil {
								_, _ = ch.Stderr().Write([]byte(err.Error()))
								status = 1
							} else {
								_, _ = ch.Write([]byte(out))
							}
							_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, status})
							ch.Close()
						}
					}()
				}
			}()
		}
	}()
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	port, _ = strconv.Atoi(p)
	return port, ssh.FingerprintSHA256(signer.PublicKey())
}

// fakeConfig is a portitor-config over https answering /api/version and
// /api/pair with the pair's fingerprints pair() gives.
func fakeConfig(t *testing.T, version string, replica func() bool, pair func() []string) (port int, fingerprint string) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"` + version + `"}`))
		case "/api/pair":
			_ = json.NewEncoder(w).Encode(pairRole{Replica: replica(), Known: true, Pair: pair()})
		default:
			http.NotFound(w, r)
		}
	}))
	// A certificate of its own: httptest's is the same for every server.
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(der)
	_, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ = strconv.Atoi(ps)
	return port, hex.EncodeToString(sum[:])
}

// An HA firewall's hosts are added one at a time; adding the second pairs
// them: the secondary's information goes from one host to the other over
// SSH, the token only on standard input, and the portal takes the witness.
// A pair already made is only checked, and the firewall is served from the
// host that is not a replica.
func TestPortalHAFirewall(t *testing.T) {
	info := testSecondaryInfo()
	info.Address = ""
	var mu sync.Mutex
	var paired bool
	var gotArgs, gotStdin string // under mu
	pairOf := func() []string {
		mu.Lock()
		defer mu.Unlock()
		if !paired {
			return nil
		}
		return []string{info.ConfigFingerprint, strings.Repeat("ab", 32)}
	}
	var refuse bool  // secondary-info refuses: in a pair already
	var flipped bool // under mu: the secondary is primary now
	isFlipped := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return flipped
	}
	priCfg, priFP := fakeConfig(t, "pri", isFlipped, pairOf)
	secCfg, secFP := fakeConfig(t, "sec", func() bool { return !isFlipped() }, pairOf)
	info.ConfigFingerprint = secFP
	infoJSON, _ := json.Marshal(info)
	portalInfo := func(port int, fp string) string {
		b, _ := json.Marshal(PortalInfo{Port: port, TLS: true, Fingerprint: fp})
		return string(b)
	}
	secPort, secKey := sshHost(t, func(cmd string, _ []byte) (string, error) {
		switch cmd {
		case "portitor-config secondary-info":
			if refuse {
				return "", errors.New("Error: this host is part of a pair or has other firewalls already")
			}
			return string(infoJSON), nil
		case "portitor-config portal-info":
			return portalInfo(secCfg, secFP), nil
		}
		return "", io.ErrUnexpectedEOF
	})
	priPort, priKey := sshHost(t, func(cmd string, stdin []byte) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case cmd == "portitor-config portal-info":
			return portalInfo(priCfg, priFP), nil
		case strings.HasPrefix(cmd, "portitor-config add-secondary"):
			gotArgs, gotStdin, paired = cmd, string(stdin), true
			return "fw1b is the HA secondary.\n", nil
		case cmd == "portitor-config witness-string":
			return (&WitnessPair{Pair: "fw1", Secret: strings.Repeat("s", 40), Hosts: []WitnessHost{
				{Name: "fw1", URL: "https://192.0.2.1:8443", Fingerprint: strings.Repeat("ab", 32)},
				{Name: "fw1b", URL: "https://192.0.2.3:8443", Fingerprint: strings.Repeat("ab", 32)},
			}}).String() + "\n", nil
		}
		return "", io.ErrUnexpectedEOF
	})
	p, err := NewPortal(&PortalConfig{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.store.PutHA(PortalHA{Name: "office", Witness: true}); err != nil {
		t.Fatal(err)
	}
	if err := p.store.PutFirewall(PortalFirewall{Name: "office", URL: "http://127.0.0.1:1"}); err == nil {
		t.Error("a firewall took an HA firewall's name")
	}

	// The primary first: its host key is confirmed before anything runs.
	req := HAHostRequest{Firewall: "office", Role: "primary", SSH: SSHProbe{Host: "127.0.0.1", Port: priPort, User: "root", Password: "pw"}}
	res, err := p.AddHAHost(t.Context(), req)
	if err != nil || !res.Confirm || res.HostKey != priKey {
		t.Fatalf("first contact: %+v %v", res, err)
	}
	req.SSH.HostKey = priKey
	if res, err = p.AddHAHost(t.Context(), req); err != nil || res.Paired || res.Warning != "" {
		t.Fatalf("primary: %+v %v", res, err)
	}

	// The secondary: not a pair yet, so the primary's login is needed.
	req = HAHostRequest{Firewall: "office", Role: "secondary", SSH: SSHProbe{Host: "127.0.0.1", Port: secPort, User: "root", Password: "pw", HostKey: secKey}}
	if _, err := p.AddHAHost(t.Context(), req); !errors.Is(err, errNeedLogin) {
		t.Fatalf("without the primary's login: %v", err)
	}
	// Through the API, that is a 409: the GUI asks for the login then.
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	client := portalClient(t, p, srv.URL)
	body, _ := json.Marshal(req)
	if r, err := client.Post(srv.URL+"/portal/v1/ha/office/secondary", "application/json", strings.NewReader(string(body))); err != nil || r.StatusCode != http.StatusConflict {
		t.Fatalf("API without the primary's login: %v %v", r, err)
	}
	req.Other = &SSHLogin{Port: priPort, User: "root", Password: "pw"}
	res, err = p.AddHAHost(t.Context(), req)
	if err != nil || !res.Paired || !res.Connected || res.Warning != "" {
		t.Fatalf("secondary: %+v %v", res, err)
	}
	mu.Lock()
	args, stdin := gotArgs, gotStdin
	mu.Unlock()
	if args != "portitor-config add-secondary --external-witness" {
		t.Errorf("command: %q", args)
	}
	var sent SecondaryInfo
	if err := json.Unmarshal([]byte(stdin), &sent); err != nil || sent.Address != "127.0.0.1" || sent.Token != info.Token {
		t.Errorf("stdin: %q %v", stdin, err)
	}
	ha, _ := p.store.HAFirewall("office")
	if ha.Primary == nil || ha.Secondary == nil || ha.Secondary.Fingerprint != secFP || ha.Secondary.SSHHostKey != secKey {
		t.Errorf("hosts: %+v", ha)
	}
	if w := p.store.Witnesses(); len(w) != 1 {
		t.Errorf("witnesses: %v", w)
	}
	// The token reached neither the portal's configuration nor its answer.
	if data, _ := p.store.Tree().JSON(datastore.JSONOptions{Secrets: true}); strings.Contains(string(data), info.Token) {
		t.Error("the token is in the portal's configuration")
	}

	// Served from the host that is not a replica, the pair known.
	sts := p.statuses(t.Context())
	if len(sts) != 1 || sts[0].Kind != "ha" || sts[0].Active != "primary" || !sts[0].Connected || sts[0].Error != "" {
		t.Errorf("status: %+v", sts)
	}
	if u := p.activeURL("office"); u.Port() != strconv.Itoa(priCfg) {
		t.Errorf("served from %v", u)
	}
	version := func(path string) string {
		t.Helper()
		r, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var v struct{ Version string }
		_ = json.NewDecoder(r.Body).Decode(&v)
		return v.Version
	}
	if v := version("/fw/office/api/version"); v != "pri" {
		t.Errorf("/fw/office/ reached %q", v)
	}
	// Each host alone, for a look at the replica.
	if v := version("/fw/office@secondary/api/version"); v != "sec" {
		t.Errorf("/fw/office@secondary/ reached %q", v)
	}
	// After a failover the pair is served by its new primary.
	mu.Lock()
	flipped = true
	mu.Unlock()
	p.statuses(t.Context())
	if v := version("/fw/office/api/version"); v != "sec" {
		t.Errorf("after the failover /fw/office/ reached %q", v)
	}

	// Added again, the secondary is a pair already: nothing is run on
	// the primary, so no login is needed.
	mu.Lock()
	gotArgs = ""
	mu.Unlock()
	req.Other = nil
	if res, err = p.AddHAHost(t.Context(), req); err != nil || res.Paired || !res.Connected {
		t.Fatalf("again: %+v %v", res, err)
	}
	mu.Lock()
	if gotArgs != "" {
		t.Errorf("paired twice: %q", gotArgs)
	}
	mu.Unlock()

	// A pair the portal can't see (no /api/pair): secondary-info's refusal
	// is taken as the pair, the host added with a warning.
	mu.Lock()
	paired = false
	mu.Unlock()
	refuse = true
	req.Other = &SSHLogin{Port: priPort, User: "root", Password: "pw"}
	if res, err = p.AddHAHost(t.Context(), req); err != nil || res.Paired || !res.Connected || res.Warning == "" {
		t.Fatalf("unseen pair: %+v %v", res, err)
	}
}
