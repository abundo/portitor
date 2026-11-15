// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// PairRequest makes a firewall the HA secondary of one the portal serves,
// without anything copied by hand: the portal reads the secondary's
// information over SSH (portitor-config secondary-info), hands it to the
// primary over SSH (add-secondary), which makes and commits the pair, adds
// the secondary to its own firewalls and, with Witness, becomes the pair's
// witness. The SSH credentials serve these connections only.
type PairRequest struct {
	// Primary is the portal's firewall that gets the secondary.
	Primary string `json:"primary"`
	// Name and Description are the secondary's in the portal; the name is
	// the secondary's host name when empty.
	Name        string `json:"name"`
	Description string `json:"description"`
	// Secondary is how to reach the new host over SSH; its HostKey is
	// empty until the administrator has confirmed it.
	Secondary SSHProbe `json:"secondary"`
	// PrimarySSH is the login to the primary's host (the host and its host
	// key are the portal's: the key was confirmed when it was added).
	PrimarySSH struct {
		Port       int    `json:"port"`
		User       string `json:"user"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
	} `json:"primary_ssh"`
	// Witness makes the portal the pair's witness.
	Witness bool `json:"witness"`
}

// PairResult is its answer: the host key to confirm, or what was done.
type PairResult struct {
	HostKey  string          `json:"host_key,omitempty"`
	Confirm  bool            `json:"confirm,omitempty"`
	Firewall *PortalFirewall `json:"firewall,omitempty"`
	// Warning says what did not work after the pair was made.
	Warning string `json:"warning,omitempty"`
}

// PairSecondary does a PairRequest.
func (p *Portal) PairSecondary(ctx context.Context, req PairRequest) (*PairResult, error) {
	var primary *PortalFirewall
	for _, f := range p.store.Firewalls() {
		if f.Name == req.Primary {
			primary = &f
		}
	}
	if primary == nil {
		return nil, fmt.Errorf("there is no firewall %s", req.Primary)
	}
	pu, err := url.Parse(primary.URL)
	if err != nil || pu.Hostname() == "" {
		return nil, fmt.Errorf("%s has no usable address", primary.Name)
	}
	if primary.SSHHostKey == "" {
		return nil, fmt.Errorf("the SSH host key of %s was not recorded when it was added: remove it and add it again", primary.Name)
	}
	if req.PrimarySSH.User == "" {
		return nil, errors.New("the login to the primary's host is needed")
	}

	sec, res, err := dialSSH(ctx, req.Secondary)
	if err != nil {
		return nil, err
	}
	if sec == nil {
		return &PairResult{HostKey: res.HostKey, Confirm: true}, nil
	}
	defer sec.Close()
	out, err := sec.run(configCommand(req.Secondary.User, "secondary-info"), nil)
	if err != nil {
		return nil, fmt.Errorf("portitor-config secondary-info on %s: %w", req.Secondary.Host, err)
	}
	var info SecondaryInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, errors.New("portitor-config secondary-info: unexpected answer")
	}
	// The address the host answered on is the one the primary will use.
	if !sec.Remote.IsValid() {
		return nil, errors.New("the secondary's address is unknown")
	}
	info.Address = sec.Remote.String()
	if req.Name != "" {
		info.Name = strings.TrimSpace(req.Name)
	}
	if err := checkSecondaryInfo(&info); err != nil {
		return nil, err
	}
	for _, f := range p.store.Firewalls() {
		if f.Name == info.Name {
			return nil, fmt.Errorf("there is a firewall %s in the portal already: give the secondary another name", info.Name)
		}
	}

	port := req.PrimarySSH.Port
	if port == 0 {
		port = 22
	}
	pri, _, err := dialSSH(ctx, SSHProbe{Host: pu.Hostname(), Port: port, User: req.PrimarySSH.User,
		Password: req.PrimarySSH.Password, PrivateKey: req.PrimarySSH.PrivateKey, HostKey: primary.SSHHostKey})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", primary.Name, err)
	}
	if pri == nil {
		return nil, fmt.Errorf("the SSH host key of %s is not the one that was confirmed when it was added", primary.Name)
	}
	defer pri.Close()
	args := []string{"add-secondary"}
	if req.Witness {
		args = append(args, "--external-witness")
	}
	body, _ := json.Marshal(info)
	if _, err := pri.run(configCommand(req.PrimarySSH.User, args...), body); err != nil {
		return nil, fmt.Errorf("portitor-config add-secondary on %s: %w", primary.Name, err)
	}

	cfgURL := "https://" + net.JoinHostPort(info.Address, strconv.Itoa(info.ConfigPort))
	fw := PortalFirewall{Name: info.Name, Description: req.Description, URL: cfgURL,
		Fingerprint: info.ConfigFingerprint, SSHHostKey: res.HostKey}
	done := &PairResult{Firewall: &fw}
	if err := p.store.PutFirewall(fw); err != nil {
		done.Warning = "the pair is made, but the portal could not add " + fw.Name + ": " + err.Error()
	}
	if req.Witness {
		wstr, err := pri.run(configCommand(req.PrimarySSH.User, "witness-string"), nil)
		if err == nil {
			err = p.store.PutWitness(strings.TrimSpace(string(wstr)))
		}
		if err != nil {
			done.Warning = strings.TrimSpace(done.Warning + " The pair's witness string was not added: " + err.Error())
		}
	}
	return done, nil
}
