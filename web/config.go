// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/goccy/go-yaml"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/dbmigrate"
)

// DefaultConfigFile is portitor-web's (PortalConfig).
const DefaultConfigFile = "/etc/portitor/web.yaml"

// DefaultLocalConfigFile is portitor-config's (Config).
const DefaultLocalConfigFile = "/etc/portitor/config.yaml"

// Config is portitor-config's /etc/portitor/config.yaml.
type Config struct {
	Bind string   `yaml:"bind"`
	DB   DBConfig `yaml:"db"`
	// JWTSecret signs session cookies. At least 32 characters.
	JWTSecret string `yaml:"jwt_secret"`
	// Dev serves the frontend from disk and drops the cookie Secure flag
	// (plain http://localhost). Never on a reachable address.
	Dev bool `yaml:"dev"`
	// TLSCert/TLSKey serve HTTPS directly; otherwise put a reverse proxy
	// in front. A certificate chosen under Settings (Portitor web) takes
	// their place once it is fetched from the agent.
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	// TrustedProxies are the addresses (CIDRs) whose X-Forwarded-For is
	// believed: portitor-web's, which passes the browser's on, so the login
	// limits count the browser's address.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// AgentURL is this host's own agent, which tells portitor-config its
	// place in an HA pair (role.go); default https://127.0.0.1:8443.
	AgentURL string `yaml:"agent_url"`
	// Local is portitor-config proper: on the firewall, for its own
	// firewall (and HA secondary) alone. Not in the file; tests run
	// without it.
	Local bool `yaml:"-"`
}

type DBConfig struct {
	// Path is the SQLite database file; its directory must be writable
	// (WAL mode keeps -wal and -shm files next to it).
	Path string `yaml:"path"`
}

const DefaultDBPath = "/var/lib/portitor-config/portitor.db"

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Bind == "" {
		cfg.Bind = "127.0.0.1:8080"
	}
	if cfg.DB.Path == "" {
		cfg.DB.Path = DefaultDBPath
	}
	if cfg.AgentURL == "" {
		cfg.AgentURL = "https://127.0.0.1:8443"
	}
	return cfg, nil
}

func (c *Config) validateForServe() error {
	if len(c.JWTSecret) < 32 {
		return errors.New("jwt_secret must be at least 32 characters")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key go together")
	}
	if _, err := c.trustedProxies(); err != nil {
		return err
	}
	return nil
}

// trustedProxies parses TrustedProxies (an address is a /32 or /128).
func (c *Config) trustedProxies() ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, p := range c.TrustedProxies {
		if !strings.Contains(p, "/") {
			if ip := net.ParseIP(p); ip != nil && ip.To4() != nil {
				p += "/32"
			} else {
				p += "/128"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %q is not an address or CIDR", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func ConnectDB(c DBConfig) (*gorm.DB, error) {
	if err := checkDBOwner(c.Path); err != nil {
		return nil, err
	}
	// Not-found is a normal answer (lookups by name), not worth logging.
	lg := logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
		SlowThreshold:             time.Second,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
	})
	db, err := dbmigrate.Open(c.Path, &gorm.Config{Logger: lg})
	if err != nil {
		return nil, fmt.Errorf("database %s: %w", c.Path, err)
	}
	return db, nil
}

// checkDBOwner refuses root when the database directory belongs to another
// user: files SQLite creates (the database, -wal, -shm) would be owned by
// root and break the service.
func checkDBOwner(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	dir := filepath.Dir(path)
	fi, err := os.Stat(dir)
	if err != nil {
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return nil
	}
	name := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	return fmt.Errorf("%s belongs to %s: run portitor-config as that user (sudo -u %s portitor-config ...)", dir, name, name)
}
