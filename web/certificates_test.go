// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

func TestCertificates(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=wan", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})
	env.vf("lab")
	env.put("instance=lab/interface=eth9", map[string]any{"kind": "physical", "enabled": true})

	cert := map[string]any{"enabled": true, "interface": "wan",
		"domains": []string{"WWW.Example.com.", " example.com"}, "email": "admin@example.com"}
	for field, v := range map[string]any{
		"interface": "eth9",
		"domains":   []string{"*.example.com"},
		"ca":        "http://ca.example.com/directory",
		"key-type":  "dsa",
		"challenge": "dns-01",
		"email":     "nobody",
	} {
		c := maps.Clone(cert)
		c[field] = v
		if rec := env.cfg("PUT", "instance=main/certificate=www", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	if rec := env.cfg("PUT", "instance=main/certificate=web%2Fserver", cert); rec.Code != http.StatusBadRequest {
		t.Errorf("bad name accepted: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/certificate=www", cert)
	if c := env.node("instance=main/certificate=www"); !slices.Equal(c.LeafLists["domains"], []string{"www.example.com", "example.com"}) ||
		c.Leaf("ca") != "letsencrypt" || c.Leaf("key-type") != "ec256" || c.Leaf("challenge") != "http-01" {
		t.Errorf("not normalised: %+v %v", c.Leaves, c.LeafLists)
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instance("main")
	if main == nil || len(main.Certificates) != 1 || main.Certificates[0].Interface != "wan" {
		t.Fatalf("document: %+v", main)
	}
	var found bool
	for _, r := range render.AutoInputRules(main) {
		found = found || (r.Service == render.ACMEHTTPService && slices.Equal(r.InInterfaces, []string{"wan"}))
	}
	if !found {
		t.Errorf("no HTTP-01 auto rule: %+v", render.AutoInputRules(main))
	}
	if rec := env.cfg("DELETE", "instance=main/interface=wan", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete used interface: %d %s", rec.Code, rec.Body)
	}
	env.mustCfg("DELETE", "instance=main/certificate=www", nil)
	env.mustCfg("DELETE", "instance=main/interface=wan", nil)
}

// testPair returns a self-signed PEM certificate for names and its key.
func testPair(t *testing.T, names ...string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
}

func TestCertificateImport(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	chain, key := testPair(t, "www.example.com", "example.com")
	_, otherKey := testPair(t, "other.example.com")
	www := "instance=main/certificate=www"

	if rec := env.cfg("PUT", www, map[string]any{"enabled": true, "source": "import", "full-chain": chain, "priv-key": otherKey}); rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched key accepted: %d %s", rec.Code, rec.Body)
	}
	env.put(www, map[string]any{"enabled": true, "source": "import", "full-chain": chain, "priv-key": key})
	if rec := env.do("GET", "/api/config/candidate/"+www, nil); strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("key shown")
	}
	if c := env.node(www); c.Leaf("interface") != "" || !slices.Equal(c.LeafLists["domains"], []string{"www.example.com", "example.com"}) {
		t.Errorf("imported: %+v %v", c.Leaves, c.LeafLists)
	}
	// An edit keeps the key; a new chain must still match it.
	env.patch(www, map[string]any{"description": "site"})
	other, _ := testPair(t, "other.example.com")
	if rec := env.cfg("PATCH", www, map[string]any{"full-chain": other}); rec.Code != http.StatusBadRequest {
		t.Errorf("chain without its key accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", www, map[string]any{"source": "acme"}); rec.Code != http.StatusBadRequest {
		t.Errorf("source changed: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instance("main")
	if main == nil || len(main.Certificates) != 1 || main.Certificates[0].PrivKey != key {
		t.Fatalf("document: %+v", main)
	}
	for _, r := range render.AutoInputRules(main) {
		if r.Service == render.ACMEHTTPService {
			t.Errorf("HTTP-01 rule for an imported certificate: %+v", r)
		}
	}
	if red := redactDoc(*doc); red.Instance("main").Certificates[0].PrivKey != "<redacted>" || main.Certificates[0].PrivKey != key {
		t.Error("key not redacted, or redacted in place")
	}
}

// A self-signed certificate is made on save and stored as an imported one.
func TestCertificateSelfSigned(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	fw := "instance=main/certificate=fw"
	for _, g := range []map[string]any{
		{"domains": []string{}, "days": 365},
		{"domains": []string{"bad name"}, "days": 365},
		{"domains": []string{"fw"}, "days": 0},
		{"domains": []string{"fw"}, "days": 365, "key-type": "dsa"},
	} {
		if rec := env.cfg("POST", fw+"?action=generate", g); rec.Code != http.StatusBadRequest {
			t.Errorf("bad request %v accepted: %d %s", g, rec.Code, rec.Body)
		}
	}
	env.mustCfg("POST", fw+"?action=generate", map[string]any{"domains": []string{"FW.example.com", "*.example.com", "192.0.2.1", "2001:db8::1"}, "key-type": "rsa2048", "days": 30})
	c := env.node(fw)
	if c.Leaf("priv-key") == "" || c.Leaf("common-name") != "fw.example.com" ||
		!slices.Equal(c.LeafLists["domains"], []string{"fw.example.com", "*.example.com", "192.0.2.1", "2001:db8::1"}) {
		t.Errorf("generated: %+v %v", c.Leaves, c.LeafLists)
	}
	b, _ := pem.Decode([]byte(c.Leaf("full-chain")))
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(leaf.NotAfter); d < 29*24*time.Hour || d > 31*24*time.Hour || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		t.Errorf("certificate: until %v", leaf.NotAfter)
	}
}

// A CA is the firewall's: made or imported on its host alone, deployed
// with the host like any imported certificate (to both hosts of a pair), it
// signs the certificates of that firewall's host and virtual firewalls.
func TestCertificateAuthority(t *testing.T) {
	env, _, _ := twoFirewalls(t)
	gen := func(inst, name string, g map[string]any) *httptest.ResponseRecorder {
		return env.cfg("POST", "instance="+inst+"/certificate="+name+"?action=generate", g)
	}
	host := "main"

	if rec := gen("guest", "ca", map[string]any{"ca": true, "days": 3650}); rec.Code != http.StatusBadRequest {
		t.Errorf("CA in a virtual firewall accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := gen(host, "ca", map[string]any{"ca": true, "domains": []string{"ca.example.com"}, "days": 3650}); rec.Code != http.StatusBadRequest {
		t.Errorf("CA with SANs accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := gen(host, "ca", map[string]any{"ca": true, "common-name": "Example CA", "days": 3650}); rec.Code != http.StatusOK {
		t.Fatalf("CA: %d %s", rec.Code, rec.Body)
	}
	ca := env.node("instance=main/certificate=ca")
	if leaf := fwconfig.ChainLeaf(ca.Leaf("full-chain")); leaf == nil || !leaf.IsCA || ca.Leaf("common-name") != "Example CA" || len(ca.LeafLists["domains"]) != 0 {
		t.Errorf("CA: %+v", ca.Leaves)
	}
	// A CA imported into a virtual firewall is refused too.
	caChain, caKey, err := acme.MakeCertificate(acme.CertRequest{CommonName: "Other CA", KeyType: "ec256", Days: 30, CA: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec := env.cfg("PUT", "instance=guest/certificate=ca2", map[string]any{"enabled": true, "source": "import", "full-chain": caChain, "priv-key": caKey}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "belongs to the firewall") {
		t.Errorf("CA imported into a virtual firewall: %d %s", rec.Code, rec.Body)
	}
	env.put("instance=main/certificate=ca2", map[string]any{"enabled": true, "source": "import", "full-chain": caChain, "priv-key": caKey})

	if rec := gen(host, "plain", map[string]any{"domains": []string{"plain.example.com"}, "days": 30}); rec.Code != http.StatusOK {
		t.Fatalf("plain: %d %s", rec.Code, rec.Body)
	}
	if rec := gen("branch", "ca", map[string]any{"ca": true, "days": 30}); rec.Code != http.StatusOK {
		t.Fatalf("branch CA: %d %s", rec.Code, rec.Body)
	}
	for _, c := range []struct{ inst, ca string }{{"guest", "plain"}, {"shop", "ca2"}, {"guest", "nope"}} {
		if rec := gen(c.inst, "www", map[string]any{"domains": []string{"www.example.com"}, "days": 30, "signed-by": c.ca}); rec.Code != http.StatusBadRequest {
			t.Errorf("%s signed by %s: %d %s", c.inst, c.ca, rec.Code, rec.Body)
		}
	}
	if rec := gen("guest", "www", map[string]any{"domains": []string{"www.example.com"}, "days": 36500, "signed-by": "ca"}); rec.Code != http.StatusOK {
		t.Fatalf("signed: %d %s", rec.Code, rec.Body)
	}
	www := env.node("instance=guest/certificate=www")
	wleaf, caLeaf := fwconfig.ChainLeaf(www.Leaf("full-chain")), fwconfig.ChainLeaf(ca.Leaf("full-chain"))
	if wleaf.IsCA || wleaf.Issuer.CommonName != "Example CA" || !wleaf.NotAfter.Equal(caLeaf.NotAfter) {
		t.Errorf("signed: %+v", wleaf.Issuer)
	}
	if rec := gen(host, "fw", map[string]any{"domains": []string{"fw.example.com"}, "days": 30, "signed-by": "ca"}); rec.Code != http.StatusOK {
		t.Errorf("signed on the host: %d %s", rec.Code, rec.Body)
	}
	if rec := env.cfg("PATCH", "instance=guest/certificate=www", map[string]any{"full-chain": ca.Leaf("full-chain")}); rec.Code != http.StatusBadRequest {
		t.Errorf("server certificate turned into a CA: %d %s", rec.Code, rec.Body)
	}

	// The CA is exported without its key, and verifies the chain.
	dl := env.do("GET", "/api/config/candidate/instance=main/certificate=ca?action=download&format=pem", nil)
	if dl.Code != http.StatusOK || strings.Contains(dl.Body.String(), "PRIVATE KEY") {
		t.Fatalf("CA download: %d %s", dl.Code, dl.Body)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(dl.Body.Bytes()) {
		t.Fatal("CA download: no certificate")
	}
	b, rest := pem.Decode([]byte(www.Leaf("full-chain")))
	leaf, _ := x509.ParseCertificate(b.Bytes)
	if b, _ = pem.Decode(rest); b == nil {
		t.Fatal("chain without its CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "www.example.com"}); err != nil {
		t.Errorf("verify: %v", err)
	}

	// The CA goes to its firewall with the host, key included.
	doc, err := builder.BuildFirewall(env.input(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, in := range doc.Instances {
		for _, c := range in.Certificates {
			if c.Name == "ca" {
				found = in.Default && c.PrivKey != ""
			}
		}
	}
	if !found {
		t.Error("CA not deployed with the host")
	}
	if rec := env.do("PUT", "/api/settings", map[string]any{"web_certificate_id": env.rowID("certificates", "ca")}); rec.Code != http.StatusBadRequest {
		t.Errorf("CA as the GUI's certificate: %d %s", rec.Code, rec.Body)
	}

	// An instance admin makes self-signed certificates only.
	tina := env.create("/api/users", map[string]string{"username": "tina", "password": "a long password", "role": "none"})
	if rec := env.do("PUT", "/api/roles/"+itoa(env.roles()["vf-guest"].ID), map[string]any{
		"members": []map[string]any{{"user_id": tina, "level": "admin"}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("role: %d %s", rec.Code, rec.Body)
	}
	env.login("tina", "a long password")
	if rec := gen("guest", "self", map[string]any{"domains": []string{"self.example.com"}, "days": 30}); rec.Code != http.StatusOK {
		t.Errorf("tenant self-signed: %d %s", rec.Code, rec.Body)
	}
	if rec := gen("guest", "signed", map[string]any{"domains": []string{"x.example.com"}, "days": 30, "signed-by": "ca"}); rec.Code < 400 {
		t.Errorf("tenant signed with the CA: %d %s", rec.Code, rec.Body)
	}
}

// A DNS-01 certificate writes through a DNS update client of its VF,
// which may be off and without records (one that only holds credentials).
func TestCertificateDNS01(t *testing.T) {
	env := newEnv(t)
	env.host("main")
	env.put("instance=main/interface=wan", map[string]any{"kind": "physical", "ipv4-mode": "dhcp", "enabled": true})
	env.put("instance=main/dns-update=acme", map[string]any{"enabled": false, "interface": "wan", "server": "192.0.2.53", "zone": "acme.example.net", "tsig-name": "acme-key", "tsig-algorithm": "hmac-sha256", "tsig-secret": "c2VjcmV0"})
	env.vf("lab")
	env.put("instance=lab/interface=eth9", map[string]any{"kind": "physical", "enabled": true})
	env.put("instance=lab/dns-update=lab", map[string]any{"enabled": false, "interface": "eth9", "server": "192.0.2.53", "zone": "example.org"})

	cert := map[string]any{"enabled": true, "challenge": "dns-01", "dns-update": "acme", "interface": "wan", "domains": []string{"*.example.com", "example.com"}}
	for field, v := range map[string]any{"dns-update": "lab", "challenge": "tls-alpn-01"} {
		c := maps.Clone(cert)
		c[field] = v
		if rec := env.cfg("PUT", "instance=main/certificate=wild", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	env.put("instance=main/certificate=wild", cert)
	if c := env.node("instance=main/certificate=wild"); c.Leaf("interface") != "" || c.Leaf("dns-update") != "acme" {
		t.Errorf("stored: %+v", c.Leaves)
	}

	doc, err := builder.Build(env.input(), 1)
	if err != nil {
		t.Fatal(err)
	}
	main := doc.Instance("main")
	if main == nil || len(main.Certificates) != 1 || len(main.DynDNS) != 0 {
		t.Fatalf("document: %+v", main)
	}
	c := main.Certificates[0]
	if d := c.DNS01; c.Interface != "" || d == nil || d.Client != "acme" || d.Zone != "acme.example.net" || d.Server != "192.0.2.53" || d.TSIG == nil || d.TSIG.Secret != "c2VjcmV0" {
		t.Errorf("certificate: %+v %+v", c, c.DNS01)
	}
	for _, r := range render.AutoInputRules(main) {
		if r.Service == render.ACMEHTTPService {
			t.Errorf("HTTP-01 auto rule for DNS-01: %+v", r)
		}
	}
	red := redactDoc(*doc)
	if r := red.Instance("main").Certificates[0].DNS01; r.TSIG.Secret != "<redacted>" || c.DNS01.TSIG.Secret != "c2VjcmV0" {
		t.Errorf("redacted: %+v, original %+v", r.TSIG, c.DNS01.TSIG)
	}
	if rec := env.cfg("DELETE", "instance=main/dns-update=acme", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("delete of a client in use: %d %s", rec.Code, rec.Body)
	}
}
