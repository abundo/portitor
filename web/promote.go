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

	"github.com/abundo/portitor/internal/datastore"
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
			if p, err := s.rec.Firewall(*me.HAPrimaryID); err == nil {
				st.Primary = p.Name
			}
		} else if peer := s.haPeerOfID(me.ID); peer != nil {
			st.Primary = peer.Name
		}
	}
	return st
}

// haPeerOfID is the firewall's HA peer, or nil.
func (s *Server) haPeerOfID(id uint) *models.Firewall {
	fws, err := s.rec.Firewalls()
	if err != nil {
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
	oldPrimary, err := s.rec.Firewall(*me.HAPrimaryID)
	if err != nil {
		return nil, err
	}
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	// The hosts move to the other firewall, which an edit refuses.
	if err := t.store.EditRaw(ctx, func(work *datastore.Tree) error {
		promoteTree(work, me.Name, oldPrimary.Name)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := s.rec.PromoteFirewalls(me, oldPrimary); err != nil {
		return nil, err
	}
	r := &s.role
	r.mu.Lock()
	r.promoted = true
	r.mu.Unlock()
	slog.Warn("ha: promoted to primary", "firewall", me.Name, "old_primary", oldPrimary.Name, "user", username, "force", force, "epoch", me.HAEpoch+1)
	noConfirm := 0
	return s.deployCandidate(ctx, username+" (promotion)", &noConfirm)
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

// promoteTree gives the configuration of the pair's primary prim to its
// secondary sec: the instances and tasks, with the two hosts' addresses
// on the pair's own links swapped, the only values of the instances they
// don't share.
func promoteTree(work *datastore.Tree, sec, prim string) {
	for _, list := range []string{"instance", "task"} {
		for _, e := range work.Root.Lists[list] {
			if e.Leaf("firewall") != prim {
				continue
			}
			e.Leaves["firewall"] = sec
			for _, ifc := range e.Lists["interface"] {
				addrs, peers := ifc.LeafLists["addresses"], ifc.LeafLists["peer-addresses"]
				if ifc.Leaf("ha-role") == "" || len(addrs) == 0 || len(peers) != len(addrs) {
					continue
				}
				ifc.LeafLists["addresses"], ifc.LeafLists["peer-addresses"] = peers, addrs
			}
		}
	}
}
