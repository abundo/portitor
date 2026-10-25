// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentclient"
	"github.com/abundo/portitor/models"
)

// An external witness (Firewall.HAWitness external) runs on a third host:
// portitor-web, or portitor-web witness alone. It is given the pair's
// witness string, which portitor-config shows on the primary (Admin ->
// Firewalls, or portitor-config witness-string): both hosts' agents, their
// certificate pins, and the witness secret, which opens nothing but the
// quorum and the vote (fwconfig.HA.WitnessSecret).

// WitnessPrefix starts a witness string.
const WitnessPrefix = "portitor-witness:"

// WitnessPair is a witness string's JSON, base64url-encoded after
// WitnessPrefix. Hosts are the primary's agent, then the secondary's.
type WitnessPair struct {
	Pair   string        `json:"pair"`
	Hosts  []WitnessHost `json:"hosts"`
	Secret string        `json:"secret"`
}

type WitnessHost struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
}

// String is the witness string.
func (w WitnessPair) String() string {
	b, _ := json.Marshal(w)
	return WitnessPrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseWitness decodes a witness string.
func ParseWitness(s string) (*WitnessPair, error) {
	s = strings.Join(strings.Fields(s), "")
	rest, ok := strings.CutPrefix(s, WitnessPrefix)
	if !ok {
		return nil, fmt.Errorf("a witness string starts with %s", WitnessPrefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(rest, "="))
	if err != nil {
		return nil, errors.New("the witness string is damaged (base64); copy it again")
	}
	var w WitnessPair
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, errors.New("the witness string is damaged (JSON); copy it again")
	}
	if len(w.Hosts) != 2 || len(w.Secret) < 32 || w.Pair == "" {
		return nil, errors.New("the witness string lacks the pair's hosts or secret")
	}
	for _, h := range w.Hosts {
		if u, err := url.Parse(h.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("witness string: %s: the agent URL must be https://", h.Name)
		}
		if len(normalizeFingerprint(h.Fingerprint)) != 64 {
			return nil, fmt.Errorf("witness string: %s: no certificate fingerprint", h.Name)
		}
	}
	return &w, nil
}

// Witness is an external witness of the pairs it is given.
type Witness struct {
	pairs []witnessTarget
	state *witness
}

type witnessTarget struct {
	name  string
	hosts [2]haHost
}

func NewWitness(strs []string) (*Witness, error) {
	w := &Witness{state: newWitnessState()}
	seen := map[string]bool{}
	for _, s := range strs {
		p, err := ParseWitness(s)
		if err != nil {
			return nil, err
		}
		if seen[p.Pair] {
			return nil, fmt.Errorf("witness: pair %s twice", p.Pair)
		}
		seen[p.Pair] = true
		t := witnessTarget{name: p.Pair}
		for i, h := range p.Hosts {
			c, err := agentclient.New(h.URL, p.Secret, h.Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("witness: %s: %w", h.Name, err)
			}
			t.hosts[i] = c
		}
		w.pairs = append(w.pairs, t)
	}
	return w, nil
}

// Run keeps the pairs' votes until ctx is cancelled.
func (w *Witness) Run(ctx context.Context) {
	for _, p := range w.pairs {
		slog.Info("witness of HA pair", "pair", p.name)
	}
	t := time.NewTicker(witnessBeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, p := range w.pairs {
			w.state.vote(ctx, p.name, p.hosts)
		}
	}
}

// witnessString is the witness string of the pair whose primary is fw,
// for its external witness.
func (s *Server) witnessString(fw *models.Firewall) (string, error) {
	if fw.HAPrimaryID != nil {
		return "", bad(fw.Name + " is a secondary: its primary has the pair's witness string")
	}
	var sec models.Firewall
	if err := s.db.Where("ha_primary_id = ?", fw.ID).First(&sec).Error; err != nil {
		return "", bad(fw.Name + " is not the primary of an HA pair")
	}
	if fw.HAWitness != models.HAWitnessExternal || fw.HAWitnessSecret == "" {
		return "", bad("the pair's witness is its portitor-config: set HA witness to external first")
	}
	w := WitnessPair{Pair: fw.Name, Secret: fw.HAWitnessSecret}
	for _, h := range []models.Firewall{*fw, sec} {
		u := h.HAURL
		if u == "" {
			u = h.AgentURL
		}
		if pu, err := url.Parse(u); err != nil || isLoopback(pu.Hostname()) {
			return "", bad(fmt.Sprintf("%s's agent URL is a loopback address, which a witness on another host can't reach; set its HA URL", h.Name))
		}
		if h.AgentFingerprint == "" {
			return "", bad(fmt.Sprintf("%s needs its agent's certificate fingerprint", h.Name))
		}
		w.Hosts = append(w.Hosts, WitnessHost{Name: h.Name, URL: u, Fingerprint: h.AgentFingerprint})
	}
	return w.String(), nil
}

// handleWitnessString gives a global admin the pair's witness string.
func (s *Server) handleWitnessString(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var fw models.Firewall
	if err := s.db.First(&fw, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	str, err := s.witnessString(&fw)
	if err != nil {
		return dbError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]string{"witness": str})
}

// WitnessString is the witness string of this portitor-config's pair, for
// the console.
func WitnessString(s *Server) (string, error) {
	var fw models.Firewall
	if err := s.db.Where("id IN (?)", s.db.Model(&models.Firewall{}).Select("ha_primary_id").Where("ha_primary_id IS NOT NULL")).First(&fw).Error; err != nil {
		return "", errors.New("no HA pair here")
	}
	str, err := s.witnessString(&fw)
	var br *badRequest
	if errors.As(err, &br) {
		return "", errors.New(br.msg)
	}
	return str, err
}
