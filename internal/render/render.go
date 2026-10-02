// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package render turns a validated fwconfig.Document into the files the
// firewall runs from: one nftables ruleset, BIND/Kea/radvd configs and a
// dnsmgr2 config per instance, and one wg(8) config per WireGuard interface.
//
// Rendering is pure (no filesystem, no commands) so the same code serves
// the agent's apply path and the GUI's preview/diff.
package render

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	dnsmgr "github.com/abundo/dnsmgr2/dnsmgr"
	"gopkg.in/yaml.v3"

	"github.com/abundo/portitor/internal/fwconfig"
)

type Paths struct {
	EtcDir       string `yaml:"etc_dir" json:"etc_dir"`
	StateDir     string `yaml:"state_dir" json:"state_dir"`
	RunDir       string `yaml:"run_dir" json:"run_dir"`
	KeaDataDir   string `yaml:"kea_data_dir" json:"kea_data_dir"`
	KeaSocketDir string `yaml:"kea_socket_dir" json:"kea_socket_dir"`
	BindCacheDir string `yaml:"bind_cache_dir" json:"bind_cache_dir"`
	BindZonesDir string `yaml:"bind_zones_dir" json:"bind_zones_dir"`
	BindRunDir   string `yaml:"bind_run_dir" json:"bind_run_dir"`
}

func DefaultPaths() Paths {
	return Paths{
		EtcDir:       "/etc/portitor",
		StateDir:     "/var/lib/portitor",
		RunDir:       "/run/portitor",
		KeaDataDir:   "/var/lib/kea",
		KeaSocketDir: "/run/kea",
		BindCacheDir: "/var/cache/bind",
		BindZonesDir: "/var/lib/bind",
		BindRunDir:   "/run/named",
	}
}

func (p Paths) InstanceEtc(name string) string {
	return filepath.Join(p.EtcDir, "instances", name)
}

func (p Paths) InstanceState(name string) string {
	return filepath.Join(p.StateDir, "instances", name)
}

// BindZones is the directory of an instance's zone files, the same path
// on the host and for named: dnsmgr2 runs on the host and writes the
// zone files' paths into named.conf.dnsmgr2. The instance's named unit
// sees only its own (a tmpfs over BindZonesDir).
func (p Paths) BindZones(name string) string {
	return filepath.Join(p.BindZonesDir, name)
}

// IPListFile holds the nft commands that fill an IP list's sets (see
// IPListElements). The agent writes it; rulesets include it.
func (p Paths) IPListFile(name string) string {
	return filepath.Join(p.StateDir, "iplists", name+".nft")
}

// CertificateDir holds an ACME certificate of an instance: the agent
// writes its chain and key there (acme.FullChainFile, acme.PrivKeyFile).
func (p Paths) CertificateDir(instance, name string) string {
	return filepath.Join(p.StateDir, "certificates", instance, name)
}

// ACMEAccountsDir holds the ACME accounts, one per CA and email.
func (p Paths) ACMEAccountsDir() string {
	return filepath.Join(p.StateDir, "acme")
}

// Units names the systemd units that run an instance's services. %s is
// the instance name (see deploy/systemd for the template units).
type Units struct {
	NamedFmt string `yaml:"named" json:"named"`
	Kea4Fmt  string `yaml:"kea4" json:"kea4"`
	Kea6Fmt  string `yaml:"kea6" json:"kea6"`
	RadvdFmt string `yaml:"radvd" json:"radvd"`
}

func DefaultUnits() Units {
	return Units{
		NamedFmt: "portitor-named@%s.service",
		Kea4Fmt:  "portitor-kea4@%s.service",
		Kea6Fmt:  "portitor-kea6@%s.service",
		RadvdFmt: "portitor-radvd@%s.service",
	}
}

func (u Units) Named(instance string) string { return fmt.Sprintf(u.NamedFmt, instance) }
func (u Units) Kea4(instance string) string  { return fmt.Sprintf(u.Kea4Fmt, instance) }
func (u Units) Kea6(instance string) string  { return fmt.Sprintf(u.Kea6Fmt, instance) }
func (u Units) Radvd(instance string) string { return fmt.Sprintf(u.RadvdFmt, instance) }

type Options struct {
	Paths       Paths
	Units       Units
	AntiLockout *AntiLockout
	// DHCPDNS holds DNS servers learned by the DHCP client, per instance
	// and interface, for DNSServer.Upstream UpstreamDHCP.
	DHCPDNS map[string]map[string][]string
	// Delegated holds the prefixes delegated to the DHCPv6 clients, which
	// the document's delegated addresses are resolved from
	// (fwconfig.Document.ResolveDelegated).
	Delegated fwconfig.DelegatedPrefixes
}

type File struct {
	Path    string      `json:"path"`
	Content string      `json:"content"`
	Mode    os.FileMode `json:"mode"`
	// Secret files hold private keys; Redacted() masks them for display.
	Secret bool `json:"secret,omitempty"`
}

// Bundle is everything rendered for one document.
type Bundle struct {
	Files []File `json:"files"`
	// Dnsmgr is the dnsmgr2 config per instance, which the agent syncs
	// from. It is also written as dnsmgr2.yaml: one complete file (host,
	// SOA and zone templates, zones and DHCP prefixes; no zones.yaml
	// include, since Portitor owns all of it), so `dnsmgr2 -c` run by hand
	// does exactly what the agent does.
	Dnsmgr map[string]dnsmgr.ConfigRoot `json:"-"`
}

// Render validates doc and renders every file.
func Render(doc fwconfig.Document, opt Options) (*Bundle, error) {
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	doc = doc.ResolveDelegated(opt.Delegated).Expand()
	b := &Bundle{Dnsmgr: map[string]dnsmgr.ConfigRoot{}}
	add := func(path, content string, mode os.FileMode, secret bool) {
		b.Files = append(b.Files, File{Path: path, Content: content, Mode: mode, Secret: secret})
	}

	for i := range doc.Instances {
		in := &doc.Instances[i]
		etc := opt.Paths.InstanceEtc(in.Name)
		add(filepath.Join(etc, "nftables.nft"), Nftables(in, opt.AntiLockout, opt.Paths), 0o644, false)

		for j := range in.Interfaces {
			ifc := &in.Interfaces[j]
			if ifc.Kind == fwconfig.KindWireGuard && ifc.WireGuard != nil {
				add(filepath.Join(etc, "wireguard", ifc.Name+".conf"), WireGuardConf(ifc), 0o600, true)
			}
		}

		if cfg, ok := DnsmgrConfig(in, opt.Paths, opt.Units); ok {
			b.Dnsmgr[in.Name] = cfg
			y, err := yaml.Marshal(cfg)
			if err != nil {
				return nil, err
			}
			add(filepath.Join(etc, "dnsmgr2.yaml"), "# Generated by portitor-agent. Do not edit.\n"+string(y), 0o644, false)
			add(filepath.Join(etc, "records.json"), RecordsJSON(in), 0o644, false)
		}
		if in.DNS.Enabled {
			add(filepath.Join(etc, "named.conf"), NamedConf(in, opt.Paths, opt.DHCPDNS[in.Name]), 0o644, false)
		}
		if in.DHCP.Enabled {
			add(filepath.Join(etc, "kea-dhcp4.conf"), KeaDhcp4Conf(in, opt.Paths), 0o644, false)
		}
		if len(DHCP6Subnets(in)) > 0 {
			add(filepath.Join(etc, "kea-dhcp6.conf"), KeaDhcp6Conf(in, opt.Paths), 0o644, false)
		}
		if len(in.RA) > 0 {
			add(filepath.Join(etc, "radvd.conf"), RadvdConf(in), 0o644, false)
		}
	}
	sort.SliceStable(b.Files, func(i, j int) bool { return b.Files[i].Path < b.Files[j].Path })
	return b, nil
}

// File returns the file at path, or nil.
func (b *Bundle) File(path string) *File {
	for i := range b.Files {
		if b.Files[i].Path == path {
			return &b.Files[i]
		}
	}
	return nil
}

var wgKeyLine = regexp.MustCompile(`(?m)^(PrivateKey|PresharedKey) = .*$`)

// Redacted returns the files with key material masked, for display.
func (b *Bundle) Redacted() []File {
	out := make([]File, len(b.Files))
	for i, f := range b.Files {
		out[i] = f
		if f.Secret {
			out[i].Content = wgKeyLine.ReplaceAllString(f.Content, "$1 = <redacted>")
		}
	}
	return out
}
