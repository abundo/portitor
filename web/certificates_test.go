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
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

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
