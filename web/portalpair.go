// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// An HA firewall's hosts are added one at a time, each over SSH as a
// firewall is (portal-info, its host key confirmed first). When the second
// one is added the portal connects them, without anything copied by hand:
// unless they are a pair already (each portitor-config names its pair's
// fingerprints, GET /api/pair), it reads the secondary's information over
// SSH (portitor-config secondary-info) and hands it to the primary over SSH
// (add-secondary), which makes and commits the pair; with the HA firewall's
// witness flag the primary names the portal as the pair's witness
// (--external-witness) and the portal takes its witness string. The
// credentials serve these connections only, and the secondary's
// information (its agent's token) is never kept.

// SSHLogin is a login to a host whose address and host key the portal has.
type SSHLogin struct {
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
}

// HAHostRequest adds a host to an HA firewall.
type HAHostRequest struct {
	// Firewall is the HA firewall, Role "primary" or "secondary".
	Firewall string `json:"firewall"`
	Role     string `json:"role"`
	// SSH reaches the new host; its HostKey is empty until the
	// administrator has confirmed it.
	SSH SSHProbe `json:"ssh"`
	// Other is the login to the host added before, needed when the two
	// are not a pair yet (the portal pairs them).
	Other *SSHLogin `json:"other,omitempty"`
}

// HAHostResult is its answer: the host key to confirm, or what was done.
type HAHostResult struct {
	HostKey string `json:"host_key,omitempty"`
	Confirm bool   `json:"confirm,omitempty"`
	// Paired: the portal paired the hosts now; Connected: they are a pair
	// (now or already).
	Paired    bool `json:"paired,omitempty"`
	Connected bool `json:"connected,omitempty"`
	// Warning says what did not work after the host was added.
	Warning string `json:"warning,omitempty"`
}

// errNeedLogin is AddHAHost's when the hosts must be paired and the login
// to the other one is missing.
var errNeedLogin = errors.New("the two hosts are not a pair yet: the login to the other host is needed to pair them")

func otherRole(role string) string {
	if role == "primary" {
		return "secondary"
	}
	return "primary"
}

// AddHAHost does an HAHostRequest.
func (p *Portal) AddHAHost(ctx context.Context, req HAHostRequest) (*HAHostResult, error) {
	ha, ok := p.store.HAFirewall(req.Firewall)
	if !ok {
		return nil, fmt.Errorf("there is no HA firewall %s", req.Firewall)
	}
	if req.Role != "primary" && req.Role != "secondary" {
		return nil, fmt.Errorf("role %q: primary or secondary", req.Role)
	}
	other := ha.Primary
	if req.Role == "primary" {
		other = ha.Secondary
	}
	if other != nil && other.SSHHostKey == "" {
		return nil, fmt.Errorf("the SSH host key of %s was not recorded: remove that host and add it again", other.Name)
	}

	conn, res, err := dialSSH(ctx, req.SSH)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return &HAHostResult{HostKey: res.HostKey, Confirm: true}, nil
	}
	defer conn.Close()
	host, err := readPortalInfo(conn, req.SSH.Host, req.SSH.User)
	if err != nil {
		return nil, err
	}
	host.Name, host.SSHHostKey = ha.Name+"/"+req.Role, res.HostKey
	check := ha
	if req.Role == "primary" {
		check.Primary = host
	} else {
		check.Secondary = host
	}
	if err := CheckPortalHA(&check); err != nil {
		return nil, err
	}
	done := &HAHostResult{}
	if other != nil {
		connected, err := areConnected(ctx, host, other)
		if err != nil {
			return nil, err
		}
		done.Connected = connected
		if !connected {
			if req.Other == nil || req.Other.User == "" {
				return nil, errNeedLogin
			}
			oc, err := dialKnown(ctx, other, *req.Other)
			if err != nil {
				return nil, err
			}
			defer oc.Close()
			sec, secUser, pri, priUser := conn, req.SSH.User, oc, req.Other.User
			if req.Role == "primary" {
				sec, secUser, pri, priUser = oc, req.Other.User, conn, req.SSH.User
			}
			err = pairHosts(sec, secUser, pri, priUser, ha.Witness)
			switch {
			case errors.Is(err, errInPair):
				// The secondary says it is in a pair already: a pair the
				// portal could not see (a portitor-config without GET
				// /api/pair). Taken as it is.
				done.Connected = true
				done.Warning = "the secondary is in a pair already, so it was added as it is; the portal could not confirm the pair (update portitor-config on both hosts)"
			case err != nil:
				return nil, err
			default:
				done.Paired, done.Connected = true, true
			}
			if done.Paired && ha.Witness {
				wstr, err := pri.run(configCommand(priUser, "witness-string"), nil)
				if err == nil {
					err = p.store.PutWitness(strings.TrimSpace(string(wstr)))
				}
				if err != nil {
					done.Warning = "the pair's witness string was not added: " + err.Error()
				}
			}
		}
	}
	if err := p.store.SetHAHost(ha.Name, req.Role, host); err != nil {
		w := "the portal could not keep the host: " + err.Error()
		if done.Paired {
			w = "the pair is made, but " + w
		}
		done.Warning = strings.TrimSpace(w + " " + done.Warning)
	}
	return done, nil
}

// readPortalInfo runs portal-info on a host: its portitor-config, which an
// HA firewall reaches over https.
func readPortalInfo(c *sshConn, addr, user string) (*PortalFirewall, error) {
	out, err := c.run(configCommand(user, "portal-info"), nil)
	if err != nil {
		return nil, fmt.Errorf("portitor-config portal-info on %s: %w", addr, err)
	}
	var info PortalInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("portitor-config portal-info: unexpected answer: %w", err)
	}
	if !info.TLS {
		return nil, errors.New("portitor-config serves plain HTTP there: an HA pair needs its tls_cert")
	}
	return &PortalFirewall{URL: "https://" + net.JoinHostPort(addr, strconv.Itoa(info.Port)), Fingerprint: info.Fingerprint}, nil
}

// dialKnown logs in to a host the portal has, its host key the one
// confirmed when it was added.
func dialKnown(ctx context.Context, h *PortalFirewall, l SSHLogin) (*sshConn, error) {
	u, err := url.Parse(h.URL)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("%s has no usable address", h.Name)
	}
	c, _, err := dialSSH(ctx, SSHProbe{Host: u.Hostname(), Port: l.Port, User: l.User,
		Password: l.Password, PrivateKey: l.PrivateKey, HostKey: h.SSHHostKey})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Name, err)
	}
	if c == nil {
		return nil, fmt.Errorf("the SSH host key of %s is not the one that was confirmed when it was added", h.Name)
	}
	return c, nil
}

// areConnected tells whether two hosts' portitor-configs are a pair: either
// names the other's fingerprint (GET /api/pair). One that does not answer
// is not known to be in a pair: secondary-info and add-secondary refuse
// what can't be paired.
func areConnected(ctx context.Context, a, b *PortalFirewall) (bool, error) {
	pairOf := func(h *PortalFirewall) ([]string, error) {
		tr, err := hostTransport(h)
		if err != nil {
			return nil, err
		}
		_, role, err := ask(ctx, &http.Client{Transport: tr, Timeout: 5 * time.Second}, h.URL)
		if err != nil {
			return nil, nil
		}
		var out []string
		for _, fp := range role.Pair {
			out = append(out, normalizeFingerprint(fp))
		}
		return out, nil
	}
	pa, err := pairOf(a)
	if err != nil {
		return false, err
	}
	pb, err := pairOf(b)
	if err != nil {
		return false, err
	}
	return slices.Contains(pa, normalizeFingerprint(b.Fingerprint)) || slices.Contains(pb, normalizeFingerprint(a.Fingerprint)), nil
}

// errInPair is pairHosts' when secondary-info refuses a host that is in a
// pair already.
var errInPair = errors.New("the secondary is in a pair already")

// pairHosts makes the host of sec the HA secondary of the host of pri:
// secondary-info there, add-secondary here with it on standard input.
func pairHosts(sec *sshConn, secUser string, pri *sshConn, priUser string, witness bool) error {
	out, err := sec.run(configCommand(secUser, "secondary-info"), nil)
	if err != nil && strings.Contains(err.Error(), "part of a pair") {
		return errInPair
	}
	if err != nil {
		return fmt.Errorf("portitor-config secondary-info on %s: %w", sec.host, err)
	}
	var info SecondaryInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return errors.New("portitor-config secondary-info: unexpected answer")
	}
	// The address the host answered on is the one the primary will use.
	if !sec.Remote.IsValid() {
		return errors.New("the secondary's address is unknown")
	}
	info.Address = sec.Remote.String()
	if err := checkSecondaryInfo(&info); err != nil {
		return err
	}
	args := []string{"add-secondary"}
	if witness {
		args = append(args, "--external-witness")
	}
	body, _ := json.Marshal(info)
	if _, err := pri.run(configCommand(priUser, args...), body); err != nil {
		return fmt.Errorf("portitor-config add-secondary on %s: %w", pri.host, err)
	}
	return nil
}
