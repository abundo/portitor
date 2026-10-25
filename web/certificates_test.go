// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
	"github.com/abundo/portitor/internal/render"
	"github.com/abundo/portitor/models"
)

func TestCertificates(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	wan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "ipv4_mode": "dhcp", "enabled": true})
	other := env.create("/api/instances", map[string]any{"name": "lab"})
	eth9 := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth9", "enabled": true})

	cert := map[string]any{
		"instance_id": inst, "name": "www", "enabled": true, "interface_id": wan,
		"domains": []string{"WWW.Example.com.", " example.com", "www.example.com"}, "email": "admin@example.com",
	}
	for field, v := range map[string]any{
		"interface_id": eth9,
		"domains":      []string{"*.example.com"},
		"ca":           "http://ca.example.com/directory",
		"key_type":     "dsa",
		"challenge":    "dns-01",
		"email":        "nobody",
		"name":         "web/server",
	} {
		c := map[string]any{}
		for k, x := range cert {
			c[k] = x
		}
		c[field] = v
		if rec := env.do("POST", "/api/certificates", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}

	rec := env.do("POST", "/api/certificates", cert)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !slices.Equal(created.Domains, []string{"www.example.com", "example.com"}) ||
		created.Ca != "letsencrypt" || created.KeyType != "ec256" || created.Challenge != "http-01" {
		t.Errorf("not normalised: %+v", created)
	}

	doc, err := builder.Build(env.srv.db, 1)
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

	if rec := env.do("DELETE", "/api/interfaces/"+itoa(wan), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "certificate www") {
		t.Errorf("delete used interface: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/certificates/"+itoa(created.ID), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("DELETE", "/api/interfaces/"+itoa(wan), nil); rec.Code != http.StatusNoContent {
		t.Errorf("delete unused interface: %d %s", rec.Code, rec.Body)
	}
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
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	chain, key := testPair(t, "www.example.com", "example.com")
	_, otherKey := testPair(t, "other.example.com")

	if rec := env.do("POST", "/api/certificates", map[string]any{"instance_id": inst, "name": "www", "enabled": true,
		"source": "import", "fullchain": chain, "privkey": otherKey}); rec.Code != http.StatusBadRequest {
		t.Errorf("mismatched key accepted: %d %s", rec.Code, rec.Body)
	}
	rec := env.do("POST", "/api/certificates", map[string]any{"instance_id": inst, "name": "www", "enabled": true,
		"source": "import", "fullchain": chain, "privkey": key})
	if rec.Code != http.StatusCreated {
		t.Fatalf("import: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("key shown")
	}
	var created models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !created.HasPrivKey || created.InterfaceID != nil || !slices.Equal(created.Domains, []string{"www.example.com", "example.com"}) {
		t.Errorf("imported: %+v", created)
	}

	// An edit keeps the key; a new chain must still match it.
	if rec := env.do("PUT", "/api/certificates/"+itoa(created.ID), map[string]any{"description": "site"}); rec.Code != http.StatusOK {
		t.Fatalf("edit: %d %s", rec.Code, rec.Body)
	}
	other, _ := testPair(t, "other.example.com")
	if rec := env.do("PUT", "/api/certificates/"+itoa(created.ID), map[string]any{"fullchain": other}); rec.Code != http.StatusBadRequest {
		t.Errorf("chain without its key accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/certificates/"+itoa(created.ID), map[string]any{"source": "acme"}); rec.Code != http.StatusBadRequest {
		t.Errorf("source changed: %d %s", rec.Code, rec.Body)
	}

	doc, err := builder.Build(env.srv.db, 1)
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
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	for _, g := range []map[string]any{
		{"domains": []string{}, "days": 365},
		{"domains": []string{"bad name"}, "days": 365},
		{"domains": []string{"fw"}, "days": 0},
		{"domains": []string{"fw"}, "days": 365, "key_type": "dsa"},
	} {
		if rec := env.do("POST", "/api/certificates", map[string]any{"instance_id": inst, "name": "fw", "enabled": true,
			"source": "import", "generate": g}); rec.Code != http.StatusBadRequest {
			t.Errorf("bad request %v accepted: %d %s", g, rec.Code, rec.Body)
		}
	}
	rec := env.do("POST", "/api/certificates", map[string]any{"instance_id": inst, "name": "fw", "enabled": true,
		"source": "import", "generate": map[string]any{
			"domains": []string{"FW.example.com", "*.example.com", "192.0.2.1", "2001:db8::1"}, "key_type": "rsa2048", "days": 30,
		}})
	if rec.Code != http.StatusCreated {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("key shown")
	}
	var created models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !created.HasPrivKey || created.CommonName != "fw.example.com" ||
		!slices.Equal(created.Domains, []string{"fw.example.com", "*.example.com", "192.0.2.1", "2001:db8::1"}) {
		t.Errorf("generated: %+v", created)
	}
	b, _ := pem.Decode([]byte(created.FullChain))
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(leaf.NotAfter); d < 29*24*time.Hour || d > 31*24*time.Hour || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		t.Errorf("certificate: until %v, %v", leaf.NotAfter, leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature))
	}
}

// A CA is the firewall's: made or imported on its host alone, deployed
// with the host like any imported certificate (to both hosts of a pair), it
// signs the certificates of that firewall's host and virtual firewalls.
func TestCertificateAuthority(t *testing.T) {
	env, _, branch := twoFirewalls(t)
	inst := func(where string, args ...any) uint {
		var in models.Instance
		if err := env.srv.db.Where(where, args...).First(&in).Error; err != nil {
			t.Fatal(err)
		}
		return in.ID
	}
	host := inst("firewall_id = 1 AND is_default")
	guest := inst("name = ?", "guest")
	branchHost := inst("firewall_id = ? AND is_default", branch)
	shop := inst("name = ?", "shop")
	gen := func(inst uint, name string, g map[string]any) *httptest.ResponseRecorder {
		return env.do("POST", "/api/certificates", map[string]any{"instance_id": inst, "name": name, "enabled": true,
			"source": "import", "generate": g})
	}

	if rec := gen(guest, "ca", map[string]any{"ca": true, "days": 3650}); rec.Code != http.StatusBadRequest {
		t.Errorf("CA in a virtual firewall accepted: %d %s", rec.Code, rec.Body)
	}
	if rec := gen(host, "ca", map[string]any{"ca": true, "domains": []string{"ca.example.com"}, "days": 3650}); rec.Code != http.StatusBadRequest {
		t.Errorf("CA with SANs accepted: %d %s", rec.Code, rec.Body)
	}
	rec := gen(host, "ca", map[string]any{"ca": true, "common_name": "Example CA", "days": 3650})
	if rec.Code != http.StatusCreated {
		t.Fatalf("CA: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Error("CA key shown")
	}
	var ca models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &ca)
	if !ca.IsCA || ca.CommonName != "Example CA" || ca.Issuer != "Example CA" || len(ca.Domains) != 0 || ca.NotAfter == nil {
		t.Errorf("CA: %+v", ca)
	}
	// A CA imported into a virtual firewall is refused too.
	caChain, caKey, err := acme.MakeCertificate(acme.CertRequest{CommonName: "Other CA", KeyType: "ec256", Days: 30, CA: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec := env.do("POST", "/api/certificates", map[string]any{"instance_id": guest, "name": "ca2", "enabled": true,
		"source": "import", "fullchain": caChain, "privkey": caKey}); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "belongs to the firewall") {
		t.Errorf("CA imported into a virtual firewall: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("POST", "/api/certificates", map[string]any{"instance_id": host, "name": "ca2", "enabled": true,
		"source": "import", "fullchain": caChain, "privkey": caKey}); rec.Code != http.StatusCreated {
		t.Errorf("CA imported on the host: %d %s", rec.Code, rec.Body)
	}

	plain := env.create("/api/certificates", map[string]any{"instance_id": host, "name": "plain", "enabled": true,
		"source": "import", "generate": map[string]any{"domains": []string{"plain.example.com"}, "days": 30}})
	branchCA := env.create("/api/certificates", map[string]any{"instance_id": branchHost, "name": "ca", "enabled": true,
		"source": "import", "generate": map[string]any{"ca": true, "days": 30}})
	for _, c := range []struct {
		inst, ca uint
	}{{guest, plain}, {guest, branchCA}, {shop, ca.ID}, {guest, 9999}} {
		if rec := gen(c.inst, "www", map[string]any{"domains": []string{"www.example.com"}, "days": 30, "ca_id": c.ca}); rec.Code != http.StatusBadRequest {
			t.Errorf("instance %d signed by %d: %d %s", c.inst, c.ca, rec.Code, rec.Body)
		}
	}
	rec = gen(guest, "www", map[string]any{"domains": []string{"www.example.com"}, "days": 36500, "ca_id": ca.ID})
	if rec.Code != http.StatusCreated {
		t.Fatalf("signed: %d %s", rec.Code, rec.Body)
	}
	var www models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &www)
	if www.IsCA || www.Issuer != "Example CA" || !www.NotAfter.Equal(*ca.NotAfter) {
		t.Errorf("signed: %+v (CA until %v)", www, ca.NotAfter)
	}
	if rec := gen(host, "fw", map[string]any{"domains": []string{"fw.example.com"}, "days": 30, "ca_id": ca.ID}); rec.Code != http.StatusCreated {
		t.Errorf("signed on the host: %d %s", rec.Code, rec.Body)
	}
	if rec := env.do("PUT", "/api/certificates/"+itoa(www.ID), map[string]any{"fullchain": ca.FullChain}); rec.Code != http.StatusBadRequest {
		t.Errorf("server certificate turned into a CA: %d %s", rec.Code, rec.Body)
	}

	// The CA is exported without its key, and verifies the chain.
	dl := env.do("GET", "/api/certificates/"+itoa(ca.ID)+"/download?format=pem", nil)
	if dl.Code != http.StatusOK || strings.Contains(dl.Body.String(), "PRIVATE KEY") {
		t.Fatalf("CA download: %d %s", dl.Code, dl.Body)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(dl.Body.Bytes()) {
		t.Fatal("CA download: no certificate")
	}
	b, rest := pem.Decode([]byte(www.FullChain))
	leaf, _ := x509.ParseCertificate(b.Bytes)
	if b, _ = pem.Decode(rest); b == nil {
		t.Fatal("chain without its CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "www.example.com"}); err != nil {
		t.Errorf("verify: %v", err)
	}

	// The CA goes to its firewall with the host, key included.
	doc, err := builder.BuildFirewall(env.srv.db, 1, 1)
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
	if rec := env.do("PUT", "/api/settings", map[string]any{"web_certificate_id": ca.ID}); rec.Code != http.StatusBadRequest {
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
	if rec := gen(guest, "self", map[string]any{"domains": []string{"self.example.com"}, "days": 30}); rec.Code != http.StatusCreated {
		t.Errorf("tenant self-signed: %d %s", rec.Code, rec.Body)
	}
	if rec := gen(guest, "signed", map[string]any{"domains": []string{"x.example.com"}, "days": 30, "ca_id": ca.ID}); rec.Code < 400 {
		t.Errorf("tenant signed with the CA: %d %s", rec.Code, rec.Body)
	}
}

// A DNS-01 certificate writes through a DNS update client of its VF,
// which may be off and without records (one that only holds credentials).
func TestCertificateDNS01(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	wan := env.create("/api/interfaces", map[string]any{"instance_id": inst, "name": "wan", "ipv4_mode": "dhcp", "enabled": true})
	dc := env.create("/api/dyndns/clients", map[string]any{
		"instance_id": inst, "name": "acme", "enabled": false, "interface_id": wan,
		"server": "192.0.2.53", "zone": "acme.example.net",
		"tsig_name": "acme-key", "tsig_algorithm": "hmac-sha256", "tsig_secret": "c2VjcmV0",
	})
	other := env.create("/api/instances", map[string]any{"name": "lab"})
	eth9 := env.create("/api/interfaces", map[string]any{"instance_id": other, "name": "eth9", "enabled": true})
	labDC := env.create("/api/dyndns/clients", map[string]any{
		"instance_id": other, "name": "lab", "interface_id": eth9, "server": "192.0.2.53", "zone": "example.org",
	})

	cert := map[string]any{
		"instance_id": inst, "name": "wild", "enabled": true, "challenge": "dns-01", "dyndns_client_id": dc,
		"interface_id": wan, "domains": []string{"*.example.com", "example.com"},
	}
	for field, v := range map[string]any{"dyndns_client_id": labDC, "challenge": "tls-alpn-01"} {
		c := maps.Clone(cert)
		c[field] = v
		if rec := env.do("POST", "/api/certificates", c); rec.Code != http.StatusBadRequest {
			t.Errorf("bad %s accepted: %d %s", field, rec.Code, rec.Body)
		}
	}
	rec := env.do("POST", "/api/certificates", cert)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created models.Certificate
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.InterfaceID != nil || created.DyndnsClientID == nil || *created.DyndnsClientID != dc {
		t.Errorf("stored: %+v", created)
	}

	doc, err := builder.Build(env.srv.db, 1)
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

	if rec := env.do("DELETE", "/api/dyndns/clients/"+itoa(dc), nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "certificate wild") {
		t.Errorf("delete of a client in use: %d %s", rec.Code, rec.Body)
	}
}
