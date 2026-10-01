// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/agentapi"
)

func TestCertificateFiles(t *testing.T) {
	a, h := testAgent(t)
	if rec := call(t, h, "GET", "/v1/certificates/main/web", testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, h, "GET", "/v1/certificates/main/..", testToken, nil); rec.Code == http.StatusOK {
		t.Fatal("bad name accepted")
	}
	if rec := call(t, h, "GET", "/v1/certificates/main/web", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"fw.example.com"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	res := &acme.Result{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
	}
	if _, err := acme.Save(a.cfg.Paths.CertificateDir("main", "web"), acme.Request{}, res); err != nil {
		t.Fatal(err)
	}
	rec := call(t, h, "GET", "/v1/certificates/main/web", testToken, nil)
	var f agentapi.CertificateFiles
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &f) != nil {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	if f.FullChain != string(res.Certificate) || f.PrivKey != string(res.PrivateKey) {
		t.Fatal("wrong files")
	}
}
