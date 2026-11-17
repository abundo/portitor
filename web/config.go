// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/goccy/go-yaml"
)

// DefaultConfigFile is portitor-manager's (PortalConfig).
const DefaultConfigFile = "/etc/portitor/manager.yaml"

// OldConfigFile is portitor-manager's before 1.1.0, read when DefaultConfigFile
// is missing, until 1.2.0.
const OldConfigFile = "/etc/portitor/web.yaml"

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
	// believed: portitor-manager's, which passes the browser's on, so the login
	// limits count the browser's address.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// AgentURL is this host's own agent, which tells portitor-config its
	// place in an HA pair (role.go); default https://127.0.0.1:8443.
	AgentURL string `yaml:"agent_url"`
	// SSHListen serves the CLI over SSH there (":2222"), to the GUI's
	// users; empty: not. The host key is ssh_host_ed25519_key in the data
	// directory.
	SSHListen string `yaml:"ssh_listen"`
	// SNMP serves the state over SNMP, as an AgentX subagent of the host's
	// snmpd (web/snmp.go).
	SNMP SNMPConfig `yaml:"snmp"`
	// Local is portitor-config proper: on the firewall, for its own
	// firewall (and HA secondary) alone. Not in the file; tests run
	// without it.
	Local bool `yaml:"-"`
}

// Dir is the directory portitor-config keeps its files in (the candidate, what
// runs of the global lists, the ids, the deployed commits, the SSH host key):
// the directory of db.path, where the database file of releases before 1.1.0
// was (the key stays: every config.yaml has it); "" for none (nothing is
// kept).
func (c *Config) Dir() string {
	if c.DB.Path == "" {
		return ""
	}
	return filepath.Dir(c.DB.Path)
}

type DBConfig struct {
	// Path names the data directory: its directory is (the file itself, the
	// database of releases before 1.1.0, is no longer read).
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

// CheckDataDir refuses root when the data directory belongs to another
// user: files it would write (the candidate, the commits, the locks) would be
// owned by root and break the service.
func CheckDataDir(c *Config) error {
	if c.Dir() == "" {
		return nil
	}
	return checkDBOwner(c.DB.Path)
}

// checkDBOwner refuses root when the directory of path belongs to another
// user.
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

// SNMPConfig is the AgentX subagent's: AgentX the master's socket (on a
// firewall by default the one the agent puts in snmpd.conf,
// fwconfig.SNMPAgentXSocket; "off" is none), BaseOID where the MIB is
// (mib.DefaultBase until Portitor has a Private Enterprise Number).
type SNMPConfig struct {
	AgentX  string `yaml:"agentx"`
	BaseOID string `yaml:"base_oid"`
}
