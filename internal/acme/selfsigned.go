// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package acme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
)

// CertRequest is a certificate MakeCertificate makes with a new key.
type CertRequest struct {
	CommonName string
	// Names are the SANs: DNS names and IP addresses.
	Names []string
	// KeyType is a fwconfig.CertKeyTypes name.
	KeyType string
	Days    int
	// CA makes a certificate authority, which signs server certificates
	// but no other CA.
	CA bool
	// IssuerChain and IssuerKey are the PEM certificate and key of the CA
	// that signs it; self-signed when empty. The certificate ends no later
	// than its CA.
	IssuerChain, IssuerKey string
}

// MakeCertificate makes a new key and a certificate for it as r asks. It
// returns the chain (the certificate, then its CA's) and the key in PEM.
func MakeCertificate(r CertRequest) (string, string, error) {
	kt, ok := KeyTypes[r.KeyType]
	if !ok {
		return "", "", fmt.Errorf("unknown key type %q", r.KeyType)
	}
	key, err := certcrypto.GeneratePrivateKey(kt)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: r.CommonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(0, 0, r.Days),
		BasicConstraintsValid: true,
	}
	if r.CA {
		tmpl.IsCA, tmpl.MaxPathLenZero = true, true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if _, ok := key.(*rsa.PrivateKey); ok {
			tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
	}
	for _, n := range r.Names {
		if ip, err := netip.ParseAddr(n); err == nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.IP(ip.AsSlice()))
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	signer := key.(crypto.Signer)
	parent, parentKey, caPEM := tmpl, signer, ""
	if r.IssuerChain != "" {
		pair, err := tls.X509KeyPair([]byte(r.IssuerChain), []byte(r.IssuerKey))
		if err != nil {
			return "", "", fmt.Errorf("CA: %w", err)
		}
		ca, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return "", "", fmt.Errorf("CA: %w", err)
		}
		if !ca.IsCA || ca.KeyUsage&x509.KeyUsageCertSign == 0 && ca.KeyUsage != 0 {
			return "", "", errors.New("CA: not a certificate authority")
		}
		if !now.Before(ca.NotAfter) {
			return "", "", errors.New("CA: expired")
		}
		if ca.NotAfter.Before(tmpl.NotAfter) {
			tmpl.NotAfter = ca.NotAfter
		}
		s, ok := pair.PrivateKey.(crypto.Signer)
		if !ok {
			return "", "", errors.New("CA: its key can't sign")
		}
		parent, parentKey = ca, s
		caPEM = string(certcrypto.PEMEncode(certcrypto.DERCertificateBytes(pair.Certificate[0])))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, signer.Public(), parentKey)
	if err != nil {
		return "", "", err
	}
	chain := string(certcrypto.PEMEncode(certcrypto.DERCertificateBytes(der))) + caPEM
	return strings.TrimSpace(chain) + "\n", string(certcrypto.PEMEncode(key)), nil
}
