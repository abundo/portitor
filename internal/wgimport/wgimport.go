// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wgimport reads a wg-quick config file: the interface's keys,
// port, addresses and MTU, and its peers. web/wgimport.go writes it into
// the configuration.
package wgimport

import (
	"bufio"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/wgkeys"
)

// Config is a wg-quick config's [Interface] and [Peer] sections.
type Config struct {
	PrivateKey string
	PublicKey  string // of PrivateKey
	ListenPort int
	// Addresses are CIDRs; an address without a length is a host's.
	Addresses []string
	MTU       int
	Peers     []Peer
	// Warnings name the keys left out: those wg-quick runs on the host
	// (DNS, PostUp, Table...), sorted.
	Warnings []string
}

// Peer is a [Peer] section. Its name is the comment line right above it
// ("# phone", "# Name = phone"), or peer<n>.
type Peer struct {
	Name         string
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
	Endpoint     string
	Keepalive    int
}

// Parse reads a wg-quick config. Its errors are for the user, with the
// line they are on.
func Parse(text string) (*Config, error) {
	cfg := &Config{}
	section, comment := "", ""
	ignored := map[string]bool{}
	ln := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if c, ok := strings.CutPrefix(line, "#"); ok {
			c = strings.TrimSpace(c)
			if k, v, ok := strings.Cut(c, "="); ok && strings.EqualFold(strings.TrimSpace(k), "name") {
				c = strings.TrimSpace(v)
			}
			comment = c
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			switch section {
			case "interface":
			case "peer":
				name := comment
				if name == "" {
					name = fmt.Sprintf("peer%d", len(cfg.Peers)+1)
				}
				cfg.Peers = append(cfg.Peers, Peer{Name: name})
			default:
				return nil, fmt.Errorf("line %d: unknown section %s", ln, line)
			}
			comment = ""
			continue
		}
		comment = ""
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", ln)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		num := func(into *int) error {
			if v == "off" {
				*into = 0
				return nil
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("line %d: %s is not a number", ln, v)
			}
			*into = n
			return nil
		}
		var err error
		switch section {
		case "interface":
			switch k {
			case "privatekey":
				cfg.PrivateKey = v
			case "listenport":
				err = num(&cfg.ListenPort)
			case "address":
				for _, a := range splitList(v) {
					if !strings.Contains(a, "/") {
						if ip, perr := netip.ParseAddr(a); perr == nil {
							a = netip.PrefixFrom(ip, ip.BitLen()).String()
						}
					}
					cfg.Addresses = append(cfg.Addresses, a)
				}
			case "mtu":
				err = num(&cfg.MTU)
			default:
				ignored["[Interface] "+k] = true
			}
		case "peer":
			p := &cfg.Peers[len(cfg.Peers)-1]
			switch k {
			case "publickey":
				p.PublicKey = v
			case "presharedkey":
				p.PresharedKey = v
			case "allowedips":
				p.AllowedIPs = append(p.AllowedIPs, splitList(v)...)
			case "endpoint":
				p.Endpoint = v
			case "persistentkeepalive":
				err = num(&p.Keepalive)
			default:
				ignored["[Peer] "+k] = true
			}
		default:
			return nil, fmt.Errorf("line %d: a key outside [Interface] or [Peer]", ln)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("the config has no [Interface] PrivateKey")
	}
	if !fwconfig.ValidWGKey(cfg.PrivateKey) {
		return nil, fmt.Errorf("PrivateKey is not a WireGuard key")
	}
	pub, err := wgkeys.Public(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	cfg.PublicKey = pub
	for _, p := range cfg.Peers {
		if p.PublicKey == "" {
			return nil, fmt.Errorf("peer %s has no PublicKey", p.Name)
		}
		if p.PresharedKey != "" && !fwconfig.ValidWGKey(p.PresharedKey) {
			return nil, fmt.Errorf("peer %s: PresharedKey is not a WireGuard key", p.Name)
		}
	}
	for k := range ignored {
		cfg.Warnings = append(cfg.Warnings, k+" is not imported")
	}
	slices.Sort(cfg.Warnings)
	return cfg, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
