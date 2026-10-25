// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// A secondary whose primary is lost is promoted on its own portitor-config
// (a replica, replica.go): its copy of the configuration becomes the
// pair's, the two swap their places (the instances and tasks move to it,
// with the primary's values and the secondary's swapped: addresses and
// peer addresses, router ids, NETs, BGP neighbours' addresses, VRRP
// priorities that are set for both), the pair's epoch goes up, and it
// commits. The old primary is then the secondary: the commit skips it
// while it is away, and catches it up when it answers (witness.go). Its
// agent, back with the document of before, hears a primary at a higher
// epoch and stays fenced until then (internal/agent/ha.go); its
// portitor-config is a replica of the new primary.
//
// Edits on the old primary that its secondary had not copied yet are
// lost, and so are the Revert snapshots, which stay on the old primary.

// haStatus is this portitor-config's place in its pair, for the GUI.
type haStatus struct {
	// Replica: read-only, a copy of the primary's configuration.
	Replica  bool       `json:"replica"`
	Node     string     `json:"node,omitempty"`
	Stale    bool       `json:"stale,omitempty"`
	Epoch    int64      `json:"epoch"`
	Primary  string     `json:"primary,omitempty"`
	Local    string     `json:"local,omitempty"`
	LastCopy *time.Time `json:"last_copy,omitempty"`
	CopyErr  string     `json:"copy_error,omitempty"`
	// PeerAlive: the agent hears its peer, so a promotion needs force.
	PeerAlive bool `json:"peer_alive"`
	Known     bool `json:"known"`
}

func (s *Server) haStatus(ctx context.Context) haStatus {
	st := haStatus{Replica: s.isReplica()}
	r := &s.role
	r.mu.Lock()
	st.Known, st.Node, st.Stale, st.Epoch, st.PeerAlive, st.CopyErr = r.known, r.peer.Node, r.peer.Stale, r.peer.Epoch, r.peer.PeerAlive, r.copyErr
	if !r.lastCopy.IsZero() {
		t := r.lastCopy
		st.LastCopy = &t
	}
	r.mu.Unlock()
	if !st.Replica {
		return st
	}
	if _, me, err := s.localHA(ctx); me != nil && err == nil {
		st.Local = me.Name
		if me.HAPrimaryID != nil {
			var p models.Firewall
			if s.db.First(&p, *me.HAPrimaryID).Error == nil {
				st.Primary = p.Name
			}
		} else if peer := haPeerOfID(s.db, me.ID); peer != nil {
			st.Primary = peer.Name
		}
	}
	return st
}

// haPeerOfID is the firewall's HA peer, or nil.
func haPeerOfID(db *gorm.DB, id uint) *models.Firewall {
	fws := []models.Firewall{}
	if db.Order("id").Find(&fws).Error != nil {
		return nil
	}
	for _, fw := range fws {
		if fw.ID == id {
			if p := haPeerOf(fws, fw); p != 0 {
				i := slices.IndexFunc(fws, func(f models.Firewall) bool { return f.ID == p })
				return &fws[i]
			}
		}
	}
	return nil
}

func (s *Server) handleHAStatus(c *echo.Context) error {
	return c.JSON(http.StatusOK, s.haStatus(c.Request().Context()))
}

func (s *Server) handlePromote(c *echo.Context) error {
	var req struct {
		Force bool `json:"force"`
	}
	_ = c.Bind(&req)
	res, err := s.Promote(c.Request().Context(), currentUser(c).Username, req.Force)
	var br *badRequest
	switch {
	case errors.As(err, &br):
		return errJSON(c, http.StatusConflict, br.msg)
	case err != nil && res != nil:
		return c.JSON(http.StatusBadGateway, map[string]any{"error": "promoted, but the commit failed: " + err.Error(), "commit": res})
	case err != nil:
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, res)
}

// Promote makes this host, the secondary, the pair's primary, and commits.
// It refuses while the agent hears the primary, unless force.
func (s *Server) Promote(ctx context.Context, username string, force bool) (*commitResult, error) {
	s.replMu.Lock()
	defer s.replMu.Unlock()
	if !s.isReplica() {
		return nil, bad("this host's configuration is its own already: there is nothing to promote")
	}
	pc, me, err := s.localHA(ctx)
	if err != nil {
		return nil, bad("this host's agent: " + err.Error())
	}
	if me.HAPrimaryID == nil {
		return nil, bad(fmt.Sprintf("in the copy of the configuration, %s is not the secondary; wait for the next copy (see the banner) or check the firewalls", me.Name))
	}
	if pc.PeerAlive && !force {
		return nil, bad("this host's agent hears the primary: promote only when the primary is lost, or force it (both then own the configuration until the old primary is caught up as the secondary)")
	}
	var oldPrimary models.Firewall
	err = s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&oldPrimary, *me.HAPrimaryID).Error; err != nil {
			return err
		}
		return promoteRows(tx, me, &oldPrimary)
	})
	if err != nil {
		return nil, err
	}
	r := &s.role
	r.mu.Lock()
	r.promoted = true
	r.mu.Unlock()
	slog.Warn("ha: promoted to primary", "firewall", me.Name, "old_primary", oldPrimary.Name, "user", username, "force", force, "epoch", me.HAEpoch+1)
	noConfirm := 0
	return s.deploy(ctx, username+" (promotion)", &noConfirm, nil)
}

// PromoteHere is Promote from the console.
func PromoteHere(ctx context.Context, s *Server, force bool) (*commitResult, error) {
	s.checkRole(ctx)
	res, err := s.Promote(ctx, consoleUser.Username, force)
	var br *badRequest
	if errors.As(err, &br) {
		return res, errors.New(br.msg)
	}
	return res, err
}

// promoteRows swaps the pair of secondary sec and primary prim: sec owns
// the instances and tasks, with their values for it, and prim is the
// secondary at the next epoch. Their agent URLs stay: each portitor-config
// reaches its own agent by its agent_url (Server.agentURL).
func promoteRows(tx *gorm.DB, sec, prim *models.Firewall) error {
	var ids []uint
	if err := tx.Model(&models.Instance{}).Where("firewall_id = ?", prim.ID).Pluck("id", &ids).Error; err != nil {
		return err
	}
	for _, m := range []any{&models.Instance{}, &models.Task{}} {
		if err := tx.Model(m).Where("firewall_id = ?", prim.ID).Update("firewall_id", sec.ID).Error; err != nil {
			return err
		}
	}
	if err := swapHAValues(tx, ids); err != nil {
		return err
	}
	witness, witnessSecret := prim.HAWitness, prim.HAWitnessSecret
	if witness == "" {
		witness = models.HAWitnessLocal
	}
	if err := tx.Model(&models.Firewall{}).Where("id = ?", sec.ID).Updates(map[string]any{
		"ha_primary_id": nil, "ha_secret": "", "ha_epoch": 0,
		"ha_witness": witness, "ha_witness_secret": witnessSecret,
	}).Error; err != nil {
		return err
	}
	return tx.Model(&models.Firewall{}).Where("id = ?", prim.ID).Updates(map[string]any{
		"ha_primary_id": sec.ID, "ha_secret": sec.HASecret, "ha_epoch": sec.HAEpoch + 1,
		"ha_witness": models.HAWitnessLocal, "ha_witness_secret": "",
	}).Error
}

// swapHAValues swaps the primary's values and the secondary's (the peer_*
// ones) of the instances.
func swapHAValues(tx *gorm.DB, ids []uint) error {
	if len(ids) == 0 {
		return nil
	}
	var ifaces []models.Interface
	if err := tx.Where("instance_id IN ?", ids).Find(&ifaces).Error; err != nil {
		return err
	}
	for _, ifc := range ifaces {
		var static, delegated models.StringList
		for _, a := range ifc.Addresses {
			if fwconfig.IsDelegated(a) {
				delegated = append(delegated, a)
			} else {
				static = append(static, a)
			}
		}
		if len(static) == 0 || len(ifc.PeerAddresses) != len(static) {
			continue
		}
		addrs := append(append(models.StringList{}, ifc.PeerAddresses...), delegated...)
		if err := tx.Model(&models.Interface{}).Where("id = ?", ifc.ID).
			Updates(map[string]any{"addresses": addrs, "peer_addresses": static}).Error; err != nil {
			return err
		}
	}
	var vrrp []models.VrrpRouter
	if err := tx.Where("instance_id IN ? AND peer_priority IS NOT NULL", ids).Find(&vrrp).Error; err != nil {
		return err
	}
	for _, r := range vrrp {
		if err := tx.Model(&models.VrrpRouter{}).Where("id = ?", r.ID).
			Updates(map[string]any{"priority": *r.PeerPriority, "peer_priority": r.Priority}).Error; err != nil {
			return err
		}
	}
	var nbrs []models.BgpNeighbor
	if err := tx.Where("instance_id IN ? AND ha_peer_address != ''", ids).Find(&nbrs).Error; err != nil {
		return err
	}
	for _, n := range nbrs {
		if err := tx.Model(&models.BgpNeighbor{}).Where("id = ?", n.ID).
			Updates(map[string]any{"address": n.HAPeerAddress, "ha_peer_address": n.Address}).Error; err != nil {
			return err
		}
	}
	for _, m := range []any{&models.BgpConfig{}, &models.OspfConfig{}} {
		if err := tx.Model(m).Where("instance_id IN ? AND router_id != '' AND peer_router_id != ''", ids).
			Updates(map[string]any{"router_id": gorm.Expr("peer_router_id"), "peer_router_id": gorm.Expr("router_id")}).Error; err != nil {
			return err
		}
	}
	return tx.Model(&models.IsisConfig{}).Where("instance_id IN ? AND net != '' AND peer_net != ''", ids).
		Updates(map[string]any{"net": gorm.Expr("peer_net"), "peer_net": gorm.Expr("net")}).Error
}
