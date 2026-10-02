// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/goccy/go-yaml"

	"github.com/abundo/portitor/internal/render"
)

// Config is /etc/portitor/agent.yaml.
type Config struct {
	// Listen is the management API address, e.g. "192.168.1.1:8443".
	Listen string `yaml:"listen"`
	// TokenFile holds the bearer token portitor-web authenticates with.
	TokenFile string `yaml:"token_file"`
	TLSCert   string `yaml:"tls_cert"`
	TLSKey    string `yaml:"tls_key"`
	// AllowFrom restricts which client addresses may call the API. The
	// same list feeds the anti-lockout rule, so these addresses keep
	// reaching the API whatever the pushed rules say.
	AllowFrom []string `yaml:"allow_from"`
	// AntiLockout adds an input accept rule for Listen's port and SSH
	// (22) from AllowFrom in the default instance. Default true.
	AntiLockout *bool `yaml:"anti_lockout"`
	// DryRun renders and logs, but changes nothing. For development on a
	// machine that is not the firewall.
	DryRun bool `yaml:"dry_run"`
	// BindUser owns BIND's working directories (bind on Debian, named on
	// Fedora).
	BindUser string       `yaml:"bind_user"`
	Paths    render.Paths `yaml:"paths"`
	Units    render.Units `yaml:"units"`
	LogLevel string       `yaml:"log_level"`
	// ConsoleUser is the account the web console's shell and command tasks
	// (fwconfig.TaskCommand) run as. "none" turns both off.
	ConsoleUser string `yaml:"console_user"`

	token string
}

const DefaultConfigFile = "/etc/portitor/agent.yaml"

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	tok, err := os.ReadFile(cfg.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("token: %w (run `portitor-agent init`)", err)
	}
	cfg.token = strings.TrimSpace(string(tok))
	if len(cfg.token) < 32 {
		return nil, errors.New("token is shorter than 32 characters")
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	def := render.DefaultPaths()
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.TokenFile == "" {
		c.TokenFile = "/etc/portitor/agent.token"
	}
	if c.BindUser == "" {
		c.BindUser = "bind"
	}
	if c.ConsoleUser == "" {
		c.ConsoleUser = "portitor"
	}
	if c.Paths.EtcDir == "" {
		c.Paths.EtcDir = def.EtcDir
	}
	if c.Paths.StateDir == "" {
		c.Paths.StateDir = def.StateDir
	}
	if c.Paths.RunDir == "" {
		c.Paths.RunDir = def.RunDir
	}
	if c.Paths.KeaDataDir == "" {
		c.Paths.KeaDataDir = def.KeaDataDir
	}
	if c.Paths.KeaSocketDir == "" {
		c.Paths.KeaSocketDir = def.KeaSocketDir
	}
	if c.Paths.BindCacheDir == "" {
		c.Paths.BindCacheDir = def.BindCacheDir
	}
	if c.Paths.BindZonesDir == "" {
		c.Paths.BindZonesDir = def.BindZonesDir
	}
	if c.Paths.BindRunDir == "" {
		c.Paths.BindRunDir = def.BindRunDir
	}
	du := render.DefaultUnits()
	if c.Units.NamedFmt == "" {
		c.Units.NamedFmt = du.NamedFmt
	}
	if c.Units.Kea4Fmt == "" {
		c.Units.Kea4Fmt = du.Kea4Fmt
	}
	if c.Units.Kea6Fmt == "" {
		c.Units.Kea6Fmt = du.Kea6Fmt
	}
	if c.Units.RadvdFmt == "" {
		c.Units.RadvdFmt = du.RadvdFmt
	}
}

func (c *Config) validate() error {
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key go together")
	}
	if c.TLSCert == "" && !c.DryRun {
		return errors.New("tls_cert/tls_key are required unless dry_run is set")
	}
	for _, a := range c.AllowFrom {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("allow_from %q: %w", a, err)
		}
	}
	for _, f := range []string{c.Units.NamedFmt, c.Units.Kea4Fmt, c.Units.Kea6Fmt, c.Units.RadvdFmt} {
		if strings.Count(f, "%s") != 1 {
			return fmt.Errorf("unit %q must contain exactly one %%s", f)
		}
	}
	return nil
}

func (c *Config) antiLockout() *render.AntiLockout {
	if c.AntiLockout != nil && !*c.AntiLockout {
		return nil
	}
	if len(c.AllowFrom) == 0 {
		return nil
	}
	port := 8443
	if i := strings.LastIndex(c.Listen, ":"); i >= 0 {
		fmt.Sscanf(c.Listen[i+1:], "%d", &port)
	}
	return &render.AntiLockout{Port: port, SSHPort: 22, AllowFrom: c.AllowFrom}
}
