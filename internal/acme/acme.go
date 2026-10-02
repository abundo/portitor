// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package acme gets certificates from an ACME CA (Let's Encrypt) through
// lego. It keeps one account per directory and email, and leaves the
// HTTP-01 challenge to a challenge.Provider of the caller's, which serves
// it where the CA's requests come in (an instance's namespace).
package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"github.com/abundo/portitor/internal/buildinfo"
)

var logOnce sync.Once

// KeyTypes maps fwconfig.CertKeyTypes to lego's.
var KeyTypes = map[string]certcrypto.KeyType{
	"ec256":   certcrypto.EC256,
	"ec384":   certcrypto.EC384,
	"rsa2048": certcrypto.RSA2048,
	"rsa3072": certcrypto.RSA3072,
	"rsa4096": certcrypto.RSA4096,
}

// Request is a certificate to get.
type Request struct {
	Directory string // ACME directory URL
	Email     string // account contact, may be empty
	KeyType   string // a KeyTypes key
	Domains   []string
	// CommonName is the subject's CN, one of Domains; empty uses the first.
	CommonName string
	HTTP01     challenge.Provider
}

// Result is a certificate and its key, PEM encoded. Certificate holds the
// chain, leaf first.
type Result struct {
	Certificate []byte
	PrivateKey  []byte
}

// Obtain registers an account (or reuses the one in accountsDir) and gets
// a certificate. It blocks until the order is done or fails; lego's
// requests have timeouts of their own.
func Obtain(accountsDir string, req Request) (*Result, error) {
	logOnce.Do(func() {
		legolog.Logger = slog.NewLogLogger(slog.Default().Handler(), slog.LevelInfo)
	})
	keyType, ok := KeyTypes[req.KeyType]
	if !ok {
		return nil, fmt.Errorf("unknown key type %q", req.KeyType)
	}
	user, err := loadAccount(accountsDir, req.Directory, req.Email)
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(user)
	cfg.CADirURL = req.Directory
	cfg.UserAgent = "portitor/" + buildinfo.Version
	cfg.Certificate.KeyType = keyType
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("ACME directory %s: %w", req.Directory, err)
	}
	if err := client.Challenge.SetHTTP01Provider(req.HTTP01); err != nil {
		return nil, err
	}
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("ACME account: %w", err)
		}
		user.Registration = reg
		if err := user.save(); err != nil {
			return nil, err
		}
	}
	// lego makes the first domain the CN.
	domains := slices.Clone(req.Domains)
	if i := slices.Index(domains, req.CommonName); i > 0 {
		domains = slices.Insert(slices.Delete(domains, i, i+1), 0, req.CommonName)
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: domains, Bundle: true})
	if err != nil {
		return nil, err
	}
	return &Result{Certificate: res.Certificate, PrivateKey: res.PrivateKey}, nil
}

// account is a lego registration.User, stored as JSON with its key.
type account struct {
	path         string
	Email        string                 `json:"email"`
	Directory    string                 `json:"directory"`
	KeyPEM       string                 `json:"key"`
	Registration *registration.Resource `json:"registration,omitempty"`
	key          crypto.PrivateKey
}

func (a *account) GetEmail() string                        { return a.Email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

// loadAccount reads the account of a directory and email, or makes a new
// key for one (registered on first use).
func loadAccount(dir, directory, email string) (*account, error) {
	sum := sha256.Sum256([]byte(directory + "\n" + email))
	a := &account{path: filepath.Join(dir, hex.EncodeToString(sum[:8])+".json"), Email: email, Directory: directory}
	data, err := os.ReadFile(a.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, a); err != nil {
			return nil, fmt.Errorf("%s: %w", a.path, err)
		}
		block, _ := pem.Decode([]byte(a.KeyPEM))
		if block == nil {
			return nil, fmt.Errorf("%s: no key", a.path)
		}
		if a.key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("%s: %w", a.path, err)
		}
		return a, nil
	case errors.Is(err, os.ErrNotExist):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		a.key = key
		a.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
		return a, a.save()
	default:
		return nil, err
	}
}

func (a *account) save() error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(a.path, data, 0o600)
}

// Stored is what a certificate's directory holds.
type Stored struct {
	// Directory and KeyType are what it was got with: a change gets a
	// new one.
	Directory string   `json:"directory"`
	KeyType   string   `json:"key_type"`
	Domains   []string `json:"domains"`
	// CommonName is the CN asked for (the CA may leave it out).
	CommonName string    `json:"common_name,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Issuer     string    `json:"issuer"`
}

// Files in a certificate's directory.
const (
	FullChainFile = "fullchain.pem"
	PrivKeyFile   = "privkey.pem"
	metaFile      = "meta.json"
)

// Save writes a certificate to dir: the chain, the key (0600) and what it
// was got with (meta.json). meta.json is removed first and written last,
// so an interrupted save leaves no certificate, and it is got again.
func Save(dir string, req Request, res *Result) (*Stored, error) {
	st, err := parse(res.Certificate)
	if err != nil {
		return nil, err
	}
	st.Directory, st.KeyType, st.CommonName = req.Directory, req.KeyType, req.CommonName
	if err := os.Remove(filepath.Join(dir, metaFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := writeFile(filepath.Join(dir, PrivKeyFile), res.PrivateKey, 0o600); err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(dir, FullChainFile), res.Certificate, 0o644); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	return st, writeFile(filepath.Join(dir, metaFile), data, 0o644)
}

// Load reads what Save wrote; nil without a (complete) certificate.
func Load(dir string) *Stored {
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if err != nil {
		return nil
	}
	var st Stored
	if json.Unmarshal(data, &st) != nil {
		return nil
	}
	return &st
}

// parse reads the leaf of a PEM chain.
func parse(chain []byte) (*Stored, error) {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no certificate in the CA's answer")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	domains := slices.Clone(c.DNSNames)
	slices.Sort(domains)
	return &Stored{Domains: domains, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Issuer: c.Issuer.String()}, nil
}

// Matches says whether st was got for req: same CA, key type, domains
// and common name.
func (st *Stored) Matches(req Request) bool {
	want := slices.Clone(req.Domains)
	for i := range want {
		want[i] = strings.ToLower(want[i])
	}
	slices.Sort(want)
	return st.Directory == req.Directory && st.KeyType == req.KeyType && st.CommonName == req.CommonName && slices.Equal(st.Domains, want)
}

// RenewAt is when a certificate is renewed: once two thirds of its
// lifetime have passed (30 days before the end of a 90-day one).
func (st *Stored) RenewAt() time.Time {
	life := st.NotAfter.Sub(st.NotBefore)
	return st.NotAfter.Add(-life / 3)
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
