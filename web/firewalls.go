// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

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
	if old == nil {
		if err := instanceNameFree(tx, f.Name); err != nil {
			return err
		}
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
	return prepareFirewall(tx, f, old)
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
func instanceNameFree(tx *gorm.DB, name string) error {
	var n int64
	if err := tx.Model(&models.Instance{}).Where("name = ?", name).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return bad(fmt.Sprintf("name: a virtual firewall is named %s", name))
	}
	return nil
}

// createFirewallInstance adds the new firewall's default instance; an HA
// secondary runs its primary's.
func createFirewallInstance(tx *gorm.DB, f *models.Firewall) error {
	if f.HAPrimaryID != nil {
		return nil
	}
	return createDefaultInstance(tx, f.ID, f.Name)
}

// createDefaultInstance creates a firewall's default instance. It logs the
// policy drops of all three chains, so a new host shows what it drops.
func createDefaultInstance(tx *gorm.DB, firewallID uint, name string) error {
	in := models.Instance{Name: name, FirewallID: firewallID,
		LogDrops: models.StringList{fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput}}
	if err := prepareInstance(tx, &in, nil); err != nil {
		return err
	}
	if !in.IsDefault {
		return fmt.Errorf("firewall %d already has a default instance", firewallID)
	}
	if err := tx.Create(&in).Error; err != nil {
		return err
	}
	return seedInstance(tx, &in)
}

// deleteFirewall refuses to delete the last firewall, or one with
// virtual firewalls besides its host; the host's instance goes with it.
func deleteFirewall(tx *gorm.DB, f *models.Firewall) error {
	var n int64
	if err := tx.Model(&models.Firewall{}).Count(&n).Error; err != nil {
		return err
	}
	if n <= 1 {
		return bad("the only firewall can't be deleted")
	}
	var secondary models.Firewall
	if err := tx.Where("ha_primary_id = ?", f.ID).First(&secondary).Error; err == nil {
		return bad(fmt.Sprintf("%s is the HA primary of %s; delete that first", f.Name, secondary.Name))
	}
	var instances []models.Instance
	if err := tx.Where("firewall_id = ?", f.ID).Find(&instances).Error; err != nil {
		return err
	}
	for _, in := range instances {
		if !in.IsDefault {
			return bad(fmt.Sprintf("virtual firewall %s is on %s; move or delete it first", in.Name, f.Name))
		}
	}
	for _, in := range instances {
		if err := deleteInstanceRows(tx, &in); err != nil {
			return err
		}
		if err := tx.Delete(&in).Error; err != nil {
			return err
		}
	}
	return nil
}

// prepareInstanceFirewall puts a new instance on a firewall (the first
// one unless it names one) and makes it that firewall's default instance
// if it has none. An instance with links stays on its firewall, and the
// default one, the host itself, never moves.
func prepareInstanceFirewall(tx *gorm.DB, in, old *models.Instance) error {
	if in.FirewallID == 0 {
		if old != nil {
			in.FirewallID = old.FirewallID
		} else {
			id, err := firstFirewallID(tx)
			if err != nil {
				return err
			}
			in.FirewallID = id
		}
	}
	var fw models.Firewall
	if err := tx.First(&fw, in.FirewallID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return bad("firewall: no such firewall")
		}
		return err
	}
	if fw.HAPrimaryID != nil {
		return bad("firewall: " + fw.Name + " is an HA secondary; it runs its primary's virtual firewalls")
	}
	if old != nil {
		in.IsDefault = old.IsDefault
		if in.FirewallID == old.FirewallID {
			return nil
		}
		if old.IsDefault {
			return bad("the default virtual firewall is its firewall's host and can't move")
		}
		var links int64
		if err := tx.Model(&models.Link{}).Where("instance_a_id = ? OR instance_b_id = ?", in.ID, in.ID).Count(&links).Error; err != nil {
			return err
		}
		if links > 0 {
			return bad("a virtual firewall with links can't move to another firewall; delete its links first")
		}
		return nil
	}
	var n int64
	if err := tx.Model(&models.Instance{}).Where("firewall_id = ? AND is_default", in.FirewallID).Count(&n).Error; err != nil {
		return err
	}
	in.IsDefault = n == 0
	if in.IsDefault {
		return nil
	}
	var st models.Settings
	if err := tx.Select("virtual_firewalls").First(&st, 1).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if !st.VirtualFirewalls {
		return bad("virtual firewalls are turned off (Settings)")
	}
	return nil
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

// sameFirewall refuses a link between instances on different firewalls.
func sameFirewall(tx *gorm.DB, a, b uint) error {
	var ins []models.Instance
	if err := tx.Select("id", "firewall_id").Where("id IN ?", []uint{a, b}).Find(&ins).Error; err != nil {
		return err
	}
	if len(ins) == 2 && ins[0].FirewallID != ins[1].FirewallID {
		return bad("a link joins virtual firewalls on the same firewall only")
	}
	return nil
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
	var in models.Instance
	err := s.db.Select("firewall_id").Where("name = ?", name).First(&in).Error
	if name == "" || errors.Is(err, gorm.ErrRecordNotFound) {
		return s.firstAgent()
	}
	if err != nil {
		return nil, nil, err
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
	var ins []models.Instance
	if err := s.db.Select("name", "firewall_id").Find(&ins).Error; err != nil {
		return nil, err
	}
	out := map[uint]map[string]bool{}
	for _, in := range ins {
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
