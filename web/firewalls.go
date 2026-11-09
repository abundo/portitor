// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Firewalls are the hosts portitor-web deploys to, each through its own
// agent. Every instance is on one firewall, and each firewall has one
// default instance: its host, created with it and named after it. A commit
// builds one document per firewall (builder.BuildFirewall).

func prepareFirewall(tx *gorm.DB, f, old *models.Firewall) error {
	f.Name = strings.TrimSpace(f.Name)
	if !fwconfig.ValidDefaultInstanceName(f.Name) {
		return bad("name: letters, digits, '-', '_' and '.', starting with a letter or digit, at most 63 characters")
	}
	f.Description = strings.TrimSpace(f.Description)
	f.AgentURL = strings.TrimRight(strings.TrimSpace(f.AgentURL), "/")
	if f.AgentURL != "" && !strings.HasPrefix(f.AgentURL, "https://") {
		return bad("agent URL must start with https://")
	}
	f.AgentFingerprint = normalizeFingerprint(f.AgentFingerprint)
	if f.AgentFingerprint != "" && len(f.AgentFingerprint) != 64 {
		return bad("fingerprint must be 64 hex characters (SHA-256)")
	}
	if t := strings.TrimSpace(f.NewAgentToken); t != "" {
		f.AgentToken = t
	}
	f.NewAgentToken = ""
	f.ConfigURL = strings.TrimRight(strings.TrimSpace(f.ConfigURL), "/")
	if f.ConfigURL != "" && !strings.HasPrefix(f.ConfigURL, "https://") {
		return bad("portitor-config URL must start with https://")
	}
	f.ConfigFingerprint = normalizeFingerprint(f.ConfigFingerprint)
	if f.ConfigFingerprint != "" && len(f.ConfigFingerprint) != 64 {
		return bad("portitor-config fingerprint must be 64 hex characters (SHA-256)")
	}
	switch f.HAWitness {
	case "":
		f.HAWitness = models.HAWitnessLocal
	case models.HAWitnessLocal, models.HAWitnessExternal:
	default:
		return bad("HA witness: local or external")
	}
	// The generation is the agent's, counted by deploys only.
	f.Generation = 0
	if old != nil {
		f.Generation = old.Generation
		// A firewall is made a secondary, or not, when it is created; a
		// promotion swaps the pair (promote.go).
		f.HAPrimaryID, f.HASecret, f.HAEpoch = old.HAPrimaryID, old.HASecret, old.HAEpoch
		f.HAWitnessSecret = old.HAWitnessSecret
		if f.HAWitness == models.HAWitnessExternal && f.HAWitnessSecret == "" {
			f.HAWitnessSecret = newHASecret()
		}
		return nil
	}
	f.HAWitnessSecret = ""
	if f.HAWitness == models.HAWitnessExternal {
		f.HAWitnessSecret = newHASecret()
	}
	if f.HAPrimaryID != nil {
		var p models.Firewall
		if err := tx.First(&p, *f.HAPrimaryID).Error; err != nil {
			return bad("HA primary: no such firewall")
		}
		if p.HAPrimaryID != nil {
			return bad("HA primary: " + p.Name + " is a secondary itself")
		}
		var n int64
		if err := tx.Model(&models.Firewall{}).Where("ha_primary_id = ?", p.ID).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			return bad("HA primary: " + p.Name + " has a secondary already")
		}
		f.HASecret = newHASecret()
	}
	return nil
}

// prepareFirewallHere is prepareFirewall; portitor-config (Local) has its
// own firewall and its HA secondary alone.
func (s *Server) prepareFirewallHere(tx *gorm.DB, f, old *models.Firewall) error {
	if s.cfg.Local && old == nil && f.HAPrimaryID == nil {
		return bad("portitor-config deploys to its own firewall (and its HA secondary); other firewalls are a manager's")
	}
	if err := prepareFirewall(tx, f, old); err != nil {
		return err
	}
	if old == nil {
		return s.instanceNameFree(f.Name)
	}
	return nil
}

func normalizeFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
}

func presentFirewall(f *models.Firewall) {
	f.HasAgentToken = f.AgentToken != ""
	f.NewAgentToken = ""
}

// instanceNameFree refuses a firewall name that a virtual firewall has:
// the firewall's default instance takes its name.
func (s *Server) instanceNameFree(name string) error {
	v, err := s.view(context.Background())
	if err != nil {
		return err
	}
	for _, in := range v.Instances {
		if in.Name == name {
			return bad(fmt.Sprintf("name: a virtual firewall is named %s", name))
		}
	}
	return nil
}

// firewallSaved gives a new firewall its default instance (an HA
// secondary runs its primary's), and makes the configuration's names of a
// renamed one follow it.
func (s *Server) firewallSaved(c *echo.Context, f, old *models.Firewall) error {
	ctx := c.Request().Context()
	if old != nil {
		return s.renameExternal(ctx, "firewalls", old.Name, f.Name)
	}
	if f.HAPrimaryID != nil {
		return nil
	}
	return s.addDefaultInstance(ctx, f.Name, f.Name)
}

// addDefaultInstance makes the candidate's default instance of the
// firewall named firewall, named name. It logs the policy drops of all
// three chains, so a new host shows what it drops.
func (s *Server) addDefaultInstance(ctx context.Context, firewall, name string) error {
	body, err := json.Marshal(map[string]any{
		"name": name, "firewall": firewall, "is-default": true,
		"log-drops": []string{fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput},
	})
	if err != nil {
		return err
	}
	return s.editConfig(ctx, func(work *datastore.Tree) error {
		for _, in := range work.Root.Lists["instance"] {
			if in.Leaf("firewall") == firewall && in.Leaf("is-default") == "true" {
				return fmt.Errorf("firewall %s already has a default instance", firewall)
			}
		}
		return work.EditJSON(datastore.Path{{Name: "instance"}}, datastore.EditCreate, body)
	})
}

// deleteFirewall refuses to delete the last firewall, or one with
// virtual firewalls besides its host, and takes its host and tasks out of
// the candidate.
func (s *Server) deleteFirewall(c *echo.Context, f *models.Firewall) error {
	var n int64
	if err := s.db.Model(&models.Firewall{}).Count(&n).Error; err != nil {
		return err
	}
	if n <= 1 {
		return bad("the only firewall can't be deleted")
	}
	var secondary models.Firewall
	if err := s.db.Where("ha_primary_id = ?", f.ID).First(&secondary).Error; err == nil {
		return bad(fmt.Sprintf("%s is the HA primary of %s; delete that first", f.Name, secondary.Name))
	}
	return s.editConfig(c.Request().Context(), func(work *datastore.Tree) error {
		for _, in := range work.Root.Lists["instance"] {
			if in.Leaf("firewall") == f.Name && in.Leaf("is-default") != "true" {
				return bad(fmt.Sprintf("virtual firewall %s is on %s; move or delete it first", in.Leaf("name"), f.Name))
			}
		}
		for _, list := range []string{"instance", "task"} {
			for _, e := range slices.Clone(work.Root.Lists[list]) {
				if e.Leaf("firewall") == f.Name {
					if err := work.Delete(datastore.PathOf(e)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// firstFirewallID is the firewall the installation started with, or the
// oldest one left.
func firstFirewallID(tx *gorm.DB) (uint, error) {
	var fw models.Firewall
	if err := tx.Order("id").First(&fw).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, bad("there is no firewall")
		}
		return 0, err
	}
	return fw.ID, nil
}

// ensureFirewall creates the first firewall if there is none.
func (s *Server) ensureFirewall() error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&models.Firewall{}).Count(&n).Error; err != nil || n > 0 {
			return err
		}
		return tx.Create(&models.Firewall{Name: "firewall"}).Error
	})
}

// firewalls lists every firewall, the first first.
func (s *Server) firewalls() ([]models.Firewall, error) {
	var fws []models.Firewall
	err := s.db.Order("id").Find(&fws).Error
	return fws, err
}

// firewallAgent is the agent of the firewall.
func (s *Server) firewallAgent(id uint) (agentAPI, *models.Firewall, error) {
	var fw models.Firewall
	if err := s.db.First(&fw, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, bad("no such firewall")
		}
		return nil, nil, err
	}
	a, err := s.newAgent(&fw)
	if err != nil {
		return nil, &fw, bad(fmt.Sprintf("firewall %s: %v", fw.Name, err))
	}
	return a, &fw, nil
}

// instanceAgent is the agent of the firewall the named instance is on.
// "", or an instance no longer in the database (deleted but still
// running), is the first firewall's.
func (s *Server) instanceAgent(name string) (agentAPI, *models.Firewall, error) {
	in, err := s.instanceNamed(context.Background(), name)
	if err != nil {
		return nil, nil, err
	}
	if in == nil {
		return s.firstAgent()
	}
	return s.firewallAgent(in.FirewallID)
}

// firstAgent is the agent of the first firewall, for what is not yet
// asked per firewall.
func (s *Server) firstAgent() (agentAPI, *models.Firewall, error) {
	id, err := firstFirewallID(s.db)
	if err != nil {
		return nil, nil, err
	}
	return s.firewallAgent(id)
}

// requestFirewall is the firewall a request names (?firewall_id=), or the
// first one.
func (s *Server) requestFirewall(c *echo.Context) (uint, error) {
	if c.QueryParam("firewall_id") == "" {
		return firstFirewallID(s.db)
	}
	id, err := echo.QueryParam[uint](c, "firewall_id")
	if err != nil {
		return 0, bad("firewall_id: not a firewall id")
	}
	return id, nil
}

// instancesOn maps each firewall id to the names of its instances.
func (s *Server) instancesOn() (map[uint]map[string]bool, error) {
	v, err := s.view(context.Background())
	if err != nil {
		return nil, err
	}
	out := map[uint]map[string]bool{}
	for _, in := range v.Instances {
		if out[in.FirewallID] == nil {
			out[in.FirewallID] = map[string]bool{}
		}
		out[in.FirewallID][in.Name] = true
	}
	return out, nil
}

// fromAll asks every firewall's agent and merges the answers into the
// first. With one firewall its error is the request's; with several, a
// firewall that can't be asked is left out (the status says why).
func fromAll[T any](ctx context.Context, s *Server, get func(agentAPI, context.Context) (*T, error), merge func(into, from *T)) (*T, error) {
	fws, err := s.firewalls()
	if err != nil {
		return nil, err
	}
	return fromFirewalls(ctx, s, fws, get, merge)
}

// fromActive is fromAll but for an HA pair's standby, whose view (its
// neighbours, its copy of the leases) is the active host's or stale: of a
// pair, only the host that reports active is asked, both when neither does.
func fromActive[T any](ctx context.Context, s *Server, get func(agentAPI, context.Context) (*T, error), merge func(into, from *T)) (*T, error) {
	fws, err := s.firewalls()
	if err != nil {
		return nil, err
	}
	return fromFirewalls(ctx, s, s.activeFirewalls(ctx, fws), get, merge)
}

// activeFirewalls is fws without the HA standbys: of each pair whose hosts
// are both in fws, the one that reports active (activeOf), or both when
// neither does or can be asked.
func (s *Server) activeFirewalls(ctx context.Context, fws []models.Firewall) []models.Firewall {
	at := map[uint]int{}
	for i, fw := range fws {
		at[fw.ID] = i
	}
	skip := map[int]bool{}
	for i, fw := range fws {
		if fw.HAPrimaryID == nil {
			continue
		}
		p, ok := at[*fw.HAPrimaryID]
		if !ok {
			continue
		}
		pair := [2]int{p, i}
		var hosts [2]haHost
		for k, j := range pair {
			if a, err := s.newAgent(&fws[j]); err == nil {
				hosts[k] = a
			}
		}
		if active := activeOf(bothOf(ctx, hosts)); active >= 0 {
			skip[pair[1-active]] = true
		}
	}
	out := make([]models.Firewall, 0, len(fws))
	for i, fw := range fws {
		if !skip[i] {
			out = append(out, fw)
		}
	}
	return out
}

// fromFirewalls asks the agents of fws and merges the answers, as fromAll.
func fromFirewalls[T any](ctx context.Context, s *Server, fws []models.Firewall, get func(agentAPI, context.Context) (*T, error), merge func(into, from *T)) (*T, error) {
	var out *T
	for _, fw := range fws {
		a, err := s.newAgent(&fw)
		var r *T
		if err == nil {
			r, err = get(a, ctx)
		}
		switch {
		case err != nil && len(fws) == 1:
			return nil, err
		case err != nil:
			slog.Debug("firewall left out", "firewall", fw.Name, "err", err)
		case out == nil:
			out = r
		default:
			merge(out, r)
		}
	}
	if out == nil {
		return nil, errors.New("no firewall answered")
	}
	return out, nil
}

// firewallFromRequest is the agent of the firewall a request names
// (?firewall_id=), or the first one's.
func (s *Server) firewallFromRequest(c *echo.Context) (agentAPI, error) {
	id, err := s.requestFirewall(c)
	if err != nil {
		return nil, err
	}
	a, _, err := s.firewallAgent(id)
	return a, err
}

// newHASecret is a new HA pair secret: 32 random bytes, URL-safe base64.
func newHASecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// handleSwitchover hands the HA pair of firewall :id over from its active
// host to its standby (as portitor request ha switchover on the active
// host). It changes no configuration.
func (s *Server) handleSwitchover(c *echo.Context) error {
	id, err := echo.PathParam[uint](c, "id")
	if err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	var fw models.Firewall
	if err := s.db.First(&fw, id).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "not found")
	}
	pair := []models.Firewall{fw}
	if fw.HAPrimaryID != nil {
		var p models.Firewall
		if err := s.db.First(&p, *fw.HAPrimaryID).Error; err != nil {
			return dbError(c, err)
		}
		pair = append(pair, p)
	} else {
		var q models.Firewall
		if err := s.db.Where("ha_primary_id = ?", fw.ID).First(&q).Error; err != nil {
			return errJSON(c, http.StatusConflict, fw.Name+" is not in an HA pair")
		}
		pair = append(pair, q)
	}
	ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
	defer cancel()
	for i := range pair {
		a, err := s.newAgent(&pair[i])
		if err != nil {
			continue
		}
		st, err := a.HA(ctx)
		if err != nil || st.State != agentapi.HAActive {
			continue
		}
		if err := a.HASwitchover(ctx); err != nil {
			return agentError(c, err)
		}
		slog.Info("ha: switchover", "from", pair[i].Name, "user", currentUser(c).Username)
		return c.JSON(http.StatusOK, map[string]string{"from": pair[i].Name})
	}
	return errJSON(c, http.StatusConflict, "no host of the pair answers as active")
}
