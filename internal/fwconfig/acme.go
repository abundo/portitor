// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// Certificate is a TLS certificate the agent gets from an ACME CA (Let's
// Encrypt) and renews before it expires. The ACME API is called from the
// host; the CA's validation requests reach the instance.
//
// With the HTTP-01 challenge the CA fetches a token over plain HTTP, port
// 80, from every domain, which must resolve to an address of Interface.
// The instance's ruleset has an input rule for port 80 on the interfaces
// of its certificates that matches only while the agent is answering a
// challenge (render.ACMEHTTPSet holds the port then, and is empty
// otherwise), so port 80 is closed the rest of the time.
//
// With the DNS-01 challenge the agent puts a TXT record at
// _acme-challenge.<domain> through a DNS update client's provider (DNS01),
// from the host like the client's own updates; the domains need not be
// reachable, and may be wildcards. A CNAME at _acme-challenge.<domain> is
// followed, so the TXT record can be in another zone, the client's.
//
// An imported certificate (Source CertSourceImport) comes with its chain
// and key, which the agent stores as they are and never renews; the ACME
// fields are empty.
type Certificate struct {
	Name string `json:"name"`
	// Source is CertSourceACME (empty) or CertSourceImport.
	Source string `json:"source,omitempty"`
	// FullChain and PrivKey are an imported certificate: the leaf first,
	// then any intermediates, and its private key, PEM.
	FullChain string `json:"fullchain,omitempty"`
	PrivKey   string `json:"privkey,omitempty"`
	// Domains are the DNS names in the certificate (its subject
	// alternative names). HTTP-01 cannot validate wildcards.
	Domains []string `json:"domains"`
	// CommonName is the subject's CN, one of Domains; empty uses the
	// first. Clients match names only against the SANs.
	CommonName string `json:"common_name,omitempty"`
	// Email is the ACME account's contact; empty registers without one.
	Email string `json:"email,omitempty"`
	// CA is an ACMECAs name or the https URL of an ACME directory.
	CA string `json:"ca"`
	// KeyType is one of CertKeyTypes.
	KeyType   string `json:"key_type"`
	Challenge string `json:"challenge"`
	// Interface is where the CA's HTTP-01 requests come in (HTTP-01
	// only).
	Interface string `json:"interface,omitempty"`
	// DNS01 is where DNS-01's TXT records are written (DNS-01 only).
	DNS01 *DNS01 `json:"dns01,omitempty"`
}

// DNS01 is a DNS update client's provider and zone, copied into a
// certificate that uses it for the DNS-01 challenge. Every
// _acme-challenge name, after its CNAMEs, must be in Zone.
type DNS01 struct {
	// Client is the DNS update client's name, for messages.
	Client string `json:"client"`
	// Provider, ProviderSettings, Server, Zone and TSIG are as in DynDNS.
	Provider         string            `json:"provider,omitempty"`
	ProviderSettings map[string]string `json:"provider_settings,omitempty"`
	Server           string            `json:"server,omitempty"`
	Zone             string            `json:"zone"`
	TSIG             *TSIG             `json:"tsig,omitempty"`
}

// Challenges.
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
)

// Challenges are the ACME challenges a certificate may use.
var Challenges = []string{ChallengeHTTP01, ChallengeDNS01}

// Certificate sources.
const (
	CertSourceACME   = "acme"
	CertSourceImport = "import"
)

// Imported says whether a certificate is imported rather than got by ACME.
func (c *Certificate) Imported() bool { return c.Source == CertSourceImport }

// HTTP01 says whether a certificate is got with the HTTP-01 challenge,
// which opens port 80 on its interface.
func (c *Certificate) HTTP01() bool { return !c.Imported() && c.Challenge == ChallengeHTTP01 }

// ParseImported checks an imported certificate: a PEM chain whose first
// certificate matches the PEM private key. It returns the leaf.
func ParseImported(chain, key string) (*x509.Certificate, error) {
	if strings.TrimSpace(chain) == "" {
		return nil, errors.New("no certificate")
	}
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("no private key")
	}
	for rest := []byte(chain); ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("certificate: a %s block in the chain", b.Type)
		}
	}
	pair, err := tls.X509KeyPair([]byte(chain), []byte(key))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(pair.Certificate[0])
}

// ChainLeaf is the first certificate of a PEM chain; nil without one.
func ChainLeaf(chain string) *x509.Certificate {
	b, _ := pem.Decode([]byte(chain))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// ACMECA is an ACME certificate authority by name.
type ACMECA struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	URL   string `json:"url"`
}

// ACMECAs are the CAs a certificate can name instead of a URL.
var ACMECAs = []ACMECA{
	{Name: "letsencrypt", Label: "Let's Encrypt", URL: "https://acme-v02.api.letsencrypt.org/directory"},
	{Name: "letsencrypt-staging", Label: "Let's Encrypt staging (test certificates)", URL: "https://acme-staging-v02.api.letsencrypt.org/directory"},
}

// CertKeyTypes are the key types of a certificate's private key.
var CertKeyTypes = []string{"ec256", "ec384", "rsa2048", "rsa3072", "rsa4096"}

// ACMEDirectory returns the directory URL of a certificate's CA.
func ACMEDirectory(ca string) (string, error) {
	for _, c := range ACMECAs {
		if c.Name == ca {
			return c.URL, nil
		}
	}
	u, err := url.Parse(ca)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" ||
		strings.ContainsFunc(ca, func(c rune) bool { return c <= 0x20 || c == 0x7f }) {
		return "", fmt.Errorf("CA must be one of %s or an https URL of an ACME directory", acmeCANames())
	}
	return ca, nil
}

func acmeCANames() string {
	var names []string
	for _, c := range ACMECAs {
		names = append(names, c.Name)
	}
	return strings.Join(names, ", ")
}

// ValidEmail is a loose check of an ACME contact address.
func ValidEmail(s string) bool {
	local, domain, ok := strings.Cut(s, "@")
	return ok && local != "" && len(s) <= 254 && validDomain(domain) && strings.Contains(domain, ".") &&
		!strings.ContainsFunc(local, func(c rune) bool { return c <= 0x20 || c == 0x7f || c == '@' || c == ',' || c == '<' || c == '>' })
}

func (v *validator) certificates(p string, in *Instance, ifaces map[string]*Interface) {
	names := map[string]bool{}
	for _, c := range in.Certificates {
		cp := fmt.Sprintf("%s: certificate %q", p, c.Name)
		if !ValidFileName(c.Name) {
			v.addf("%s: invalid name", cp)
		}
		if names[c.Name] {
			v.addf("%s: duplicate", cp)
		}
		names[c.Name] = true
		switch c.Source {
		case "", CertSourceACME:
		case CertSourceImport:
			if _, err := ParseImported(c.FullChain, c.PrivKey); err != nil {
				v.addf("%s: %v", cp, err)
			}
			if c.Interface != "" || c.DNS01 != nil || c.CA != "" || c.KeyType != "" || c.Challenge != "" || c.Email != "" || c.CommonName != "" || len(c.Domains) > 0 {
				v.addf("%s: an imported certificate has no ACME settings", cp)
			}
			continue
		default:
			v.addf("%s: source must be %s or %s", cp, CertSourceACME, CertSourceImport)
			continue
		}
		if c.FullChain != "" || c.PrivKey != "" {
			v.addf("%s: an ACME certificate has no imported chain or key", cp)
		}
		switch c.Challenge {
		case ChallengeHTTP01:
			if ifaces[c.Interface] == nil {
				v.addf("%s: unknown interface %q", cp, c.Interface)
			}
			if c.DNS01 != nil {
				v.addf("%s: HTTP-01 has no DNS update client", cp)
			}
		case ChallengeDNS01:
			if c.Interface != "" {
				v.addf("%s: DNS-01 has no interface", cp)
			}
			if d := c.DNS01; d == nil {
				v.addf("%s: DNS-01 needs a DNS update client", cp)
			} else {
				dp := fmt.Sprintf("%s: dns update %q", cp, d.Client)
				v.dnsProvider(dp, DynDNS{Provider: d.Provider, ProviderSettings: d.ProviderSettings, Server: d.Server, TSIG: d.TSIG})
				v.tsig(dp, d.Provider, d.TSIG)
				if !validDomain(d.Zone) {
					v.addf("%s: invalid zone %q", dp, d.Zone)
				}
			}
		default:
			v.addf("%s: challenge must be one of %s", cp, strings.Join(Challenges, ", "))
		}
		if _, err := ACMEDirectory(c.CA); err != nil {
			v.addf("%s: %v", cp, err)
		}
		if !slices.Contains(CertKeyTypes, c.KeyType) {
			v.addf("%s: key type must be one of %s", cp, strings.Join(CertKeyTypes, ", "))
		}
		if c.Email != "" && !ValidEmail(c.Email) {
			v.addf("%s: invalid email %q", cp, c.Email)
		}
		if len(c.Domains) == 0 || len(c.Domains) > 100 {
			v.addf("%s: needs 1-100 domains", cp)
		}
		seen := map[string]bool{}
		for _, d := range c.Domains {
			if err := CertDomain(d, c.Challenge); err != nil {
				v.addf("%s: %v", cp, err)
			}
			if seen[d] {
				v.addf("%s: domain %q twice", cp, d)
			}
			seen[d] = true
		}
		if c.CommonName != "" {
			if len(c.CommonName) > 64 {
				v.addf("%s: common name longer than 64 characters", cp)
			}
			if !seen[c.CommonName] {
				v.addf("%s: common name %q is not one of the domains", cp, c.CommonName)
			}
		}
	}
}

// CertDomain checks a certificate's domain: a lower-case DNS name with at
// least two labels and no trailing dot, not an address, and a wildcard
// only with DNS-01.
func CertDomain(d, challenge string) error {
	if _, err := netip.ParseAddr(d); err == nil {
		return fmt.Errorf("%q: an IP address can't be validated", d)
	}
	if rest, ok := strings.CutPrefix(d, "*."); ok {
		if challenge != ChallengeDNS01 {
			return fmt.Errorf("%q: only DNS-01 can validate a wildcard", d)
		}
		d = rest
	}
	if d != strings.ToLower(d) || strings.HasSuffix(d, ".") || !strings.Contains(d, ".") || !validDomain(d) || strings.Contains(d, "_") {
		return fmt.Errorf("%q is not a DNS name (lower case, no trailing dot)", d)
	}
	return nil
}
