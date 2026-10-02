// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// InitFiles creates the API token and a self-signed TLS certificate if they
// don't exist, and returns the certificate's SHA-256 fingerprint, which
// portitor-web pins instead of trusting a CA.
func InitFiles(tokenFile, certFile, keyFile string, hosts []string) (token, fingerprint string, err error) {
	if data, err := os.ReadFile(tokenFile); err == nil {
		token = strings.TrimSpace(string(data))
	} else {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return "", "", err
		}
		token = base64.RawURLEncoding.EncodeToString(buf)
		if err := atomicWrite(tokenFile, []byte(token+"\n"), 0o600); err != nil {
			return "", "", err
		}
	}

	if _, err := os.Stat(certFile); errors.Is(err, os.ErrNotExist) {
		if err := generateCert(certFile, keyFile, hosts); err != nil {
			return "", "", err
		}
	}
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", "", fmt.Errorf("%s: no PEM certificate", certFile)
	}
	sum := sha256.Sum256(block.Bytes)
	return token, hex.EncodeToString(sum[:]), nil
}

func generateCert(certFile, keyFile string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "portitor-agent " + hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range append(hosts, hostname, "localhost") {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := atomicWrite(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return atomicWrite(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}
