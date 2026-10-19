// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

type proxyUser struct {
	key *ecdsa.PrivateKey
	reg *registration.Resource
}

func (u *proxyUser) GetEmail() string                        { return "" }
func (u *proxyUser) GetRegistration() *registration.Resource { return u.reg }
func (u *proxyUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type noChallenge struct{}

func (noChallenge) Present(string, string, string) error { return nil }
func (noChallenge) CleanUp(string, string, string) error { return nil }

func freePort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestACMEProxy(t *testing.T) {
	dns01 := func(client string) *fwconfig.DNS01 {
		return &fwconfig.DNS01{Client: client, Server: "192.0.2.53", Zone: "example.com"}
	}
	cfg := fwconfig.ACMEProxy{
		Port: freePort(t), Interfaces: []string{"lan"}, CA: "letsencrypt-staging",
		Policies: []fwconfig.ACMEProxyPolicy{
			{Name: "web", Domains: []string{"*.web.example.com"}, Sources: []string{"127.0.0.0/8"}, DNS01: dns01("a")},
			{Name: "mail", Domains: []string{"mail.example.com"}, DNS01: dns01("b")},
			{Name: "remote", Domains: []string{"far.example.com"}, Sources: []string{"10.0.0.0/8"}, DNS01: dns01("a")},
		},
	}
	paths := render.Paths{StateDir: t.TempDir()}
	m := newACMEProxyManager(false, paths, newCertManager(false, paths, nil))

	var mu sync.Mutex
	var authorized [][]string
	var providers map[string]bool
	m.authorize = func(_ string, req acme.Request) error {
		mu.Lock()
		defer mu.Unlock()
		authorized = append(authorized, req.Domains)
		return nil
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "upstream"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	m.obtain = func(_ string, req acme.Request, csr *x509.CertificateRequest) ([]byte, error) {
		mu.Lock()
		p := req.DNS01.(*multiDNS01)
		providers = map[string]bool{}
		for n := range p.by {
			providers[n] = true
		}
		mu.Unlock()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
	}
	m.validate = func(_ context.Context, it acmeProxyItem, name, _, _ string, client netip.Addr) error {
		if it.cfg.Policy(name, client) == nil {
			return errors.New("no policy")
		}
		return nil
	}
	m.Reconcile([]acmeProxyItem{{instance: "main", cfg: cfg, addrs: []string{"127.0.0.1/8"}}})
	defer m.Stop()

	st := m.Status()
	if len(st) != 1 || st[0].State != "running" || !strings.Contains(st[0].SelfSigned, "BEGIN CERTIFICATE") {
		t.Fatalf("status %+v", st)
	}
	// The client trusts the self-signed certificate, as it is told to.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(st[0].SelfSigned))
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u := &proxyUser{key: key}
	lc := lego.NewConfig(u)
	lc.CADirURL = "https://127.0.0.1:" + strconv.Itoa(cfg.Port) + "/directory"
	lc.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second}
	lc.Certificate.Timeout = 5 * time.Second
	client, err := lego.NewClient(lc)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Challenge.SetHTTP01Provider(noChallenge{})
	if u.reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		t.Fatal(err)
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{"www.web.example.com", "mail.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Certificate), "BEGIN CERTIFICATE") {
		t.Errorf("certificate %q", res.Certificate)
	}
	mu.Lock()
	if len(authorized) != 1 || strings.Join(authorized[0], ",") != "mail.example.com,www.web.example.com" {
		t.Errorf("authorized upstream %v", authorized)
	}
	if !providers["mail.example.com"] || !providers["www.web.example.com"] {
		t.Errorf("DNS-01 providers for %v", providers)
	}
	mu.Unlock()

	// Not from 127.0.0.1: far.example.com's policy is 10.0.0.0/8's; a
	// name no policy has.
	for _, name := range []string{"far.example.com", "web.example.com"} {
		if _, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{name}}); err == nil || !strings.Contains(err.Error(), "no policy allows") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}

	st = m.Status()
	if len(st[0].Issued) != 1 || st[0].Issued[0].Error != "" || st[0].Issued[0].NotAfter == nil || st[0].Issued[0].Client != "127.0.0.1" {
		t.Errorf("issued %+v", st[0].Issued)
	}
	// The log and the accounts are kept over a restart.
	m.Stop()
	if got := loadIssued(paths.ACMEProxyDir("main")); len(got) != 1 {
		t.Errorf("issue log %+v", got)
	}
}

func TestACMEProxyPolicy(t *testing.T) {
	x := fwconfig.ACMEProxy{Policies: []fwconfig.ACMEProxyPolicy{
		{Name: "a", Domains: []string{"*.lan.example", "lan.example"}, Sources: []string{"192.168.1.0/24"}},
		{Name: "b", Domains: []string{"*.lan.example"}},
	}}
	for _, c := range []struct {
		name, addr, want string
	}{
		{"www.lan.example", "192.168.1.5", "a"},
		{"www.lan.example", "10.0.0.1", "b"},
		{"lan.example", "192.168.1.5", "a"},
		{"lan.example", "10.0.0.1", ""},
		{"a.b.lan.example", "10.0.0.1", "b"},
		{"xlan.example", "192.168.1.5", ""},
	} {
		got := ""
		if p := x.Policy(c.name, netip.MustParseAddr(c.addr)); p != nil {
			got = p.Name
		}
		if got != c.want {
			t.Errorf("%s from %s: policy %q, want %q", c.name, c.addr, got, c.want)
		}
	}
	if x.Clients() != nil {
		t.Errorf("clients %v: policy b has no sources", x.Clients())
	}
}

// An HTTP-01 policy's names are answered upstream by the HTTP-01 server;
// an order mixing them with DNS-01 names is refused.
func TestACMEProxyUpstreamHTTP01(t *testing.T) {
	cfg := fwconfig.ACMEProxy{CA: "letsencrypt-staging", Policies: []fwconfig.ACMEProxyPolicy{
		{Name: "web", Domains: []string{"*.web.example.com"}, Challenge: fwconfig.ChallengeHTTP01, Interface: "wan"},
		{Name: "lan", Domains: []string{"*.lan.example.com"}, DNS01: &fwconfig.DNS01{Client: "a", Server: "192.0.2.53", Zone: "example.com"}},
	}}
	paths := render.Paths{StateDir: t.TempDir()}
	m := newACMEProxyManager(false, paths, newCertManager(false, paths, nil))
	it := acmeProxyItem{instance: "main", cfg: cfg}
	client := netip.MustParseAddr("192.168.1.5")

	req, done, err := m.upstream(it, []string{"a.web.example.com", "b.web.example.com"}, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req.HTTP01.(*http01Server); !ok || req.DNS01 != nil {
		t.Errorf("HTTP-01 request %+v", req)
	}
	done()

	req, done, err = m.upstream(it, []string{"a.lan.example.com"}, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := req.DNS01.(*multiDNS01); !ok || req.HTTP01 != nil {
		t.Errorf("DNS-01 request %+v", req)
	}
	done()

	if _, _, err := m.upstream(it, []string{"a.web.example.com", "a.lan.example.com"}, client); err == nil || !strings.Contains(err.Error(), "different challenges") {
		t.Errorf("mixed challenges: %v", err)
	}
}
