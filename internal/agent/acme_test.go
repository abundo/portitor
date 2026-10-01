// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

// nftRunner records the nft scripts it is given, by namespace.
type nftRunner struct {
	mu      sync.Mutex
	scripts []string
}

func (r *nftRunner) Run(ctx context.Context, netns, name string, args ...string) ([]byte, error) {
	return r.RunInput(ctx, netns, nil, name, args...)
}

func (r *nftRunner) RunInput(_ context.Context, netns string, stdin []byte, _ string, _ ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scripts = append(r.scripts, netns+": "+string(stdin))
	return nil, nil
}

func testCert(t *testing.T, domains []string) *acme.Result {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: domains, NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	return &acme.Result{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
	}
}

func waitState(t *testing.T, m *certManager, state string) CertificateStatus {
	t.Helper()
	for range 200 {
		if st := m.Status(); len(st) == 1 && st[0].State == state {
			return st[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state never %s: %+v", state, m.Status())
	return CertificateStatus{}
}

func TestCertManager(t *testing.T) {
	paths := render.Paths{StateDir: t.TempDir()}
	run := &nftRunner{}
	m := newCertManager(false, paths, run)
	var mu sync.Mutex
	orders := 0
	fail := true
	m.obtain = func(accountsDir string, req acme.Request) (*acme.Result, error) {
		mu.Lock()
		defer mu.Unlock()
		orders++
		if accountsDir != paths.ACMEAccountsDir() || req.Directory != fwconfig.ACMECAs[0].URL || req.HTTP01 == nil {
			t.Errorf("request %s %+v", accountsDir, req)
		}
		if fail {
			return nil, errors.New("rate limited")
		}
		return testCert(t, req.Domains), nil
	}
	item := certItem{instance: "main", netns: "fw-main", cfg: fwconfig.Certificate{
		Name: "www", Domains: []string{"www.example.com"}, CA: "letsencrypt", KeyType: "ec256", Challenge: fwconfig.ChallengeHTTP01, Interface: "wan",
	}}
	m.Reconcile(context.Background(), []certItem{item})
	st := waitState(t, m, "error")
	if st.LastError != "rate limited" || st.NextAttempt == nil {
		t.Errorf("status %+v", st)
	}

	// A changed certificate starts again, and is ordered at once.
	mu.Lock()
	fail = false
	mu.Unlock()
	item.cfg.Email = "admin@example.com"
	m.Reconcile(context.Background(), []certItem{item})
	st = waitState(t, m, "ok")
	if st.NotAfter == nil || st.Dir != paths.CertificateDir("main", "www") {
		t.Errorf("status %+v", st)
	}
	if _, err := os.Stat(filepath.Join(st.Dir, acme.FullChainFile)); err != nil {
		t.Error(err)
	}

	// Unchanged: no new order. A new manager (agent restart) finds the
	// stored certificate.
	m.Reconcile(context.Background(), []certItem{item})
	m.Stop()
	m2 := newCertManager(false, paths, run)
	m2.obtain = m.obtain
	m2.Reconcile(context.Background(), []certItem{item})
	waitState(t, m2, "ok")
	m2.Stop()
	mu.Lock()
	defer mu.Unlock()
	if orders != 2 {
		t.Errorf("%d orders, want 2", orders)
	}
}

// An apply reloads the ruleset, emptying the set: Reconcile fills it again
// where a challenge is being answered.
func TestCertManagerReopensPort(t *testing.T) {
	run := &nftRunner{}
	m := newCertManager(false, render.Paths{StateDir: t.TempDir()}, run)
	m.open["fw-main"] = 1
	m.Reconcile(context.Background(), nil)
	if len(run.scripts) != 1 || run.scripts[0] != "fw-main: "+render.ACMEHTTPOpen {
		t.Errorf("scripts %q", run.scripts)
	}
}

func TestHTTP01Serve(t *testing.T) {
	p := &http01Server{tokens: map[string]string{"tok": "tok.thumb"}}
	for path, want := range map[string]int{
		"/.well-known/acme-challenge/tok":   200,
		"/.well-known/acme-challenge/other": 404,
		"/tok":                              404,
	} {
		w := httptest.NewRecorder()
		p.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want || (want == 200 && w.Body.String() != "tok.thumb") {
			t.Errorf("%s: %d %q", path, w.Code, w.Body.String())
		}
	}
}
