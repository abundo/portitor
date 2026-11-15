// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

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

// The portal pairs a secondary with a primary it serves: the secondary's
// information goes from one host to the other over SSH, the token only on
// standard input, and the portal adds the secondary and the witness.
func TestPortalPair(t *testing.T) {
	info := testSecondaryInfo()
	info.Address = ""
	infoJSON, _ := json.Marshal(info)
	var mu sync.Mutex
	var gotArgs, gotStdin string // under mu
	secPort, secKey := sshHost(t, func(cmd string, _ []byte) (string, error) {
		if cmd != "portitor-config secondary-info" {
			return "", io.ErrUnexpectedEOF
		}
		return string(infoJSON), nil
	})
	priPort, priKey := sshHost(t, func(cmd string, stdin []byte) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasPrefix(cmd, "portitor-config add-secondary"):
			gotArgs, gotStdin = cmd, string(stdin)
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
	if err := p.store.PutFirewall(PortalFirewall{Name: "fw1", URL: "https://127.0.0.1:443", Fingerprint: strings.Repeat("ab", 32), SSHHostKey: priKey}); err != nil {
		t.Fatal(err)
	}
	req := PairRequest{Primary: "fw1", Witness: true}
	req.Secondary = SSHProbe{Host: "127.0.0.1", Port: secPort, User: "root", Password: "pw"}
	req.PrimarySSH.Port, req.PrimarySSH.User, req.PrimarySSH.Password = priPort, "root", "pw"

	// The secondary's host key is confirmed first; nothing is run before.
	res, err := p.PairSecondary(t.Context(), req)
	if err != nil || !res.Confirm || res.HostKey != secKey {
		t.Fatalf("first contact: %+v %v", res, err)
	}
	req.Secondary.HostKey = secKey
	res, err = p.PairSecondary(t.Context(), req)
	if err != nil || res.Firewall == nil || res.Warning != "" {
		t.Fatalf("pair: %+v %v", res, err)
	}
	mu.Lock()
	args, stdin := gotArgs, gotStdin
	mu.Unlock()
	if args != "portitor-config add-secondary --external-witness" {
		t.Errorf("command: %q", args)
	}
	var sent SecondaryInfo
	if err := json.Unmarshal([]byte(stdin), &sent); err != nil || sent.Address != "127.0.0.1" || sent.Token != info.Token || sent.Name != "fw1b" {
		t.Errorf("stdin: %q %v", stdin, err)
	}
	var found bool
	for _, f := range p.store.Firewalls() {
		if f.Name == "fw1b" && f.URL == "https://127.0.0.1:443" && f.Fingerprint == info.ConfigFingerprint && f.SSHHostKey == secKey {
			found = true
		}
	}
	if !found {
		t.Errorf("firewalls: %+v", p.store.Firewalls())
	}
	if w := p.store.Witnesses(); len(w) != 1 {
		t.Errorf("witnesses: %v", w)
	}
	// The token reached neither the portal's configuration nor its answer.
	if data, _ := p.store.Tree().JSON(datastore.JSONOptions{}); strings.Contains(string(data), info.Token) {
		t.Error("the token is in the portal's configuration")
	}
	// The same name again is refused before the primary is touched.
	if _, err := p.PairSecondary(t.Context(), req); err == nil {
		t.Error("a name in use was accepted")
	}
	// A primary whose host key differs is refused.
	if err := p.store.PutFirewall(PortalFirewall{Name: "fw1", URL: "https://127.0.0.1:443", Fingerprint: strings.Repeat("ab", 32), SSHHostKey: "SHA256:other"}); err != nil {
		t.Fatal(err)
	}
	req.Name = "fw1c"
	if _, err := p.PairSecondary(t.Context(), req); err == nil {
		t.Error("another host key on the primary was accepted")
	}
}
