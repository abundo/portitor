// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
)

// Pairing an HA secondary without copying anything by hand: on the
// secondary `portitor-config secondary-info` prints what the primary needs
// (SecondaryInfo), and on the primary `portitor-config add-secondary` reads
// it on standard input and makes the pair. portitor-web (the portal) runs
// both over SSH and carries the JSON between them; the setup's
// `portitor-setup --join` runs add-secondary with the same data from a
// secondary string. The token travels on standard input only.

// SecondaryInfo is what a primary needs to add a host as its HA secondary.
type SecondaryInfo struct {
	// Name is the host's short name, the firewall's name in the pair.
	Name string `json:"name"`
	// Address is the host's management address, filled in by whoever
	// carries the information (the portal: the address it reached the host
	// on). With or without a prefix length: the primary's management
	// network decides it.
	Address string `json:"address,omitempty"`
	// AgentPort and ConfigPort are those of the agent and portitor-config.
	AgentPort  int `json:"agent_port"`
	ConfigPort int `json:"config_port"`
	// Token is the agent's token: a secret.
	Token             string `json:"token"`
	AgentFingerprint  string `json:"agent_fingerprint"`
	ConfigFingerprint string `json:"config_fingerprint"`
}

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ReadSecondaryInfo is `portitor-config secondary-info`, on a host whose
// portitor-config has its own agent and nothing else yet: a secondary
// before it is paired.
func ReadSecondaryInfo(s *Server, cfg *Config) (*SecondaryInfo, error) {
	fws, err := s.rec.Firewalls()
	if err != nil {
		return nil, err
	}
	if len(fws) != 1 {
		return nil, errors.New("this host is part of a pair or has other firewalls already: only a new host can be added as an HA secondary")
	}
	fw := fws[0]
	if fw.AgentToken == "" || fw.AgentFingerprint == "" {
		return nil, errors.New("this host's portitor-config has no agent yet (portitor-config set-agent)")
	}
	pi, err := ReadPortalInfo(cfg)
	if err != nil {
		return nil, err
	}
	if !pi.TLS {
		return nil, errors.New("portitor-config serves plain HTTP here: the pair needs its tls_cert")
	}
	agentPort := 0
	if u, err := url.Parse(fw.AgentURL); err == nil {
		_, _ = fmt.Sscan(u.Port(), &agentPort)
	}
	if agentPort == 0 {
		agentPort = 8443
	}
	name, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	name, _, _ = strings.Cut(name, ".")
	if !fwconfig.ValidDefaultInstanceName(name) {
		return nil, fmt.Errorf("the host name %q is no firewall name: letters, digits, '-', '_' and '.', starting with a letter or digit", name)
	}
	return &SecondaryInfo{
		Name: name, AgentPort: agentPort, ConfigPort: pi.Port, Token: fw.AgentToken,
		AgentFingerprint: fw.AgentFingerprint, ConfigFingerprint: pi.Fingerprint,
	}, nil
}

// consoleJSON runs an API request as the console admin and decodes its answer into out.
func (s *Server) consoleJSON(ctx context.Context, method, path string, body, out any) error {
	var data []byte
	if body != nil {
		var err error
		if data, err = json.Marshal(body); err != nil {
			return err
		}
	}
	code, ans := s.ConsoleRequest(ctx, method, path, data)
	if code/100 != 2 {
		var e struct {
			Error    string   `json:"error"`
			Problems []string `json:"problems"`
		}
		_ = json.Unmarshal(ans, &e)
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(ans))
		}
		if len(e.Problems) > 0 {
			msg += ": " + strings.Join(e.Problems, "; ")
		}
		return fmt.Errorf("%s %s: %d %s", method, path, code, msg)
	}
	if out != nil && len(ans) > 0 {
		return json.Unmarshal(ans, out)
	}
	return nil
}

// AddSecondary is `portitor-config add-secondary`, on the primary: adds the
// host of info as its HA secondary, gives the management interface its
// peer address, and commits the pair (confirmed at once: the pair is the
// change, and a failed commit says so). With externalWitness the pair's
// witness is a third host's (portitor-config witness-string gives its string).
func AddSecondary(ctx context.Context, s *Server, info SecondaryInfo, externalWitness bool) error {
	if err := checkSecondaryInfo(&info); err != nil {
		return err
	}
	fws, err := s.rec.Firewalls()
	if err != nil {
		return err
	}
	var own *uint
	for _, f := range fws {
		if f.HAPrimaryID == nil {
			id := f.ID
			own = &id
			break
		}
	}
	if own == nil {
		return errors.New("no firewall in portitor-config")
	}
	for _, f := range fws {
		if f.HAPrimaryID != nil && *f.HAPrimaryID == *own {
			return fmt.Errorf("this host has an HA secondary already (%s; Admin -> Firewalls)", f.Name)
		}
		if f.Name == info.Name {
			return fmt.Errorf("there is a firewall %s already", info.Name)
		}
	}
	var insts []map[string]any
	if err := s.consoleJSON(ctx, http.MethodGet, "/api/config/candidate/instance?shallow", nil, &insts); err != nil {
		return err
	}
	inst := ""
	for _, i := range insts {
		if d, _ := i["is-default"].(bool); d {
			inst, _ = i["name"].(string)
		}
	}
	if inst == "" {
		return errors.New("no default virtual firewall")
	}
	ifPath := "/api/config/candidate/instance=" + url.PathEscape(inst) + "/interface"
	var ifs []map[string]any
	if err := s.consoleJSON(ctx, http.MethodGet, ifPath+"?shallow", nil, &ifs); err != nil {
		return err
	}
	var mgmt string
	var mgmtAddr netip.Prefix
	haLink := false
	for _, i := range ifs {
		switch i["ha-role"] {
		case "ha_link":
			haLink = true
		case "management":
			mgmt, _ = i["name"].(string)
			if addrs, _ := i["addresses"].([]any); len(addrs) > 0 {
				if a, _ := addrs[0].(string); a != "" {
					mgmtAddr, _ = netip.ParsePrefix(a)
				}
			}
		}
	}
	if !haLink {
		return errors.New("this host has no HA link interface: run the primary's setup first")
	}
	if mgmt == "" || !mgmtAddr.IsValid() {
		return errors.New("this host has no management interface with an address: run the primary's setup first")
	}
	peer, err := peerAddress(info.Address, mgmtAddr)
	if err != nil {
		return err
	}
	if err := s.consoleJSON(ctx, http.MethodPost, "/api/firewalls", map[string]any{
		"name":               info.Name,
		"agent_url":          "https://" + hostPort(peer.Addr(), info.AgentPort),
		"agent_token":        info.Token,
		"agent_fingerprint":  info.AgentFingerprint,
		"config_url":         "https://" + hostPort(peer.Addr(), info.ConfigPort),
		"config_fingerprint": info.ConfigFingerprint,
		"ha_primary_id":      *own,
	}, nil); err != nil {
		return err
	}
	if err := s.consoleJSON(ctx, http.MethodPatch, ifPath+"="+url.PathEscape(mgmt),
		map[string]any{"peer-addresses": []string{peer.String()}}, nil); err != nil {
		return err
	}
	if externalWitness {
		if err := s.consoleJSON(ctx, http.MethodPut, fmt.Sprintf("/api/firewalls/%d", *own),
			map[string]any{"ha_witness": "external"}, nil); err != nil {
			return err
		}
	}
	var res struct {
		Status string `json:"status"`
	}
	if err := s.consoleJSON(ctx, http.MethodPost, "/api/deploy/apply", map[string]any{"confirm_timeout": 300}, &res); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if res.Status == "pending" {
		if err := s.consoleJSON(ctx, http.MethodPost, "/api/deploy/confirm", map[string]any{}, nil); err != nil {
			return fmt.Errorf("confirm: %w", err)
		}
	}
	return nil
}

// checkSecondaryInfo checks what came in, which may come from anywhere.
func checkSecondaryInfo(i *SecondaryInfo) error {
	i.AgentFingerprint = strings.ToLower(i.AgentFingerprint)
	i.ConfigFingerprint = strings.ToLower(i.ConfigFingerprint)
	switch {
	case !fwconfig.ValidDefaultInstanceName(i.Name):
		return errors.New("the secondary's name is no firewall name")
	case !fingerprintRE.MatchString(i.AgentFingerprint), !fingerprintRE.MatchString(i.ConfigFingerprint):
		return errors.New("a fingerprint is not 64 hex characters")
	case len(strings.TrimSpace(i.Token)) < 16:
		return errors.New("the agent token is missing")
	case i.AgentPort < 1 || i.AgentPort > 65535 || i.ConfigPort < 1 || i.ConfigPort > 65535:
		return errors.New("a port is out of range")
	}
	i.Token = strings.TrimSpace(i.Token)
	return nil
}

// peerAddress is the secondary's management address with the prefix of the
// primary's: they must be two hosts of one network.
func peerAddress(text string, own netip.Prefix) (netip.Prefix, error) {
	var a netip.Addr
	if p, err := netip.ParsePrefix(text); err == nil {
		a = p.Addr()
	} else if a, err = netip.ParseAddr(text); err != nil {
		return netip.Prefix{}, fmt.Errorf("the secondary's management address %q is no IP address", text)
	}
	a = a.Unmap()
	if !a.Is4() || !own.Addr().Is4() {
		return netip.Prefix{}, errors.New("the management addresses must be IPv4")
	}
	peer := netip.PrefixFrom(a, own.Bits())
	if peer.Masked() != own.Masked() || a == own.Addr() {
		return netip.Prefix{}, fmt.Errorf("the secondary's management address %s is not another address in %s", a, own.Masked())
	}
	return peer, nil
}

func hostPort(a netip.Addr, port int) string {
	return netip.AddrPortFrom(a, uint16(port)).String()
}
