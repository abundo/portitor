// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/internal/snmp/agentx"
	"github.com/abundo/portitor/internal/snmp/mib"
	"github.com/abundo/portitor/models"
)

// SNMP: portitor-config serves the YANG state (web/state.go) read-only over
// SNMP as an AgentX subagent of the host's snmpd, which the agent runs
// with "master agentx" while SNMP is on in the default virtual firewall.
// The objects are internal/snmp/mib's, under snmp.base_oid.

// snmpUser is who the state is asked for as: a global viewer, so every
// virtual firewall's (the host's SNMP is the firewall's).
var snmpUser = &models.User{Username: "snmp", Role: models.RoleViewer}

// snmpRefresh is how old a snapshot of the state may be; snmpd waits about
// a second for a subagent, so it is refreshed behind the answers.
const snmpRefresh = 10 * time.Second

// MIBText is PORTITOR-MIB under cfg's base OID (portitor-config mib).
func MIBText(cfg *Config) (string, error) {
	m, err := (&Server{cfg: cfg}).SNMPMIB()
	if err != nil {
		return "", err
	}
	root, err := schema.Load()
	if err != nil {
		return "", err
	}
	return m.Text(root.Revision), nil
}

// SNMPMIB is the state's MIB under the configured base OID.
func (s *Server) SNMPMIB() (*mib.MIB, error) {
	base := s.cfg.SNMP.BaseOID
	if base == "" {
		base = mib.DefaultBase
	}
	oid, err := agentx.ParseOID(base)
	if err != nil {
		return nil, err
	}
	reg, err := mib.LoadRegistry()
	if err != nil {
		return nil, err
	}
	root, err := schema.Load()
	if err != nil {
		return nil, err
	}
	return mib.New(root, oid, reg, false), nil
}

// snmpSocket is the AgentX master's socket, "" for none.
func (s *Server) snmpSocket() string {
	switch {
	case s.cfg.SNMP.AgentX == "off":
		return ""
	case s.cfg.SNMP.AgentX != "":
		return s.cfg.SNMP.AgentX
	case s.cfg.Local:
		return fwconfig.SNMPAgentXSocket
	}
	return ""
}

func (s *Server) runSNMP(ctx context.Context) {
	sock := s.snmpSocket()
	if sock == "" {
		return
	}
	m, err := s.SNMPMIB()
	if err != nil {
		slog.Error("snmp: the MIB", "err", err)
		return
	}
	h := &snmpState{s: s, m: m, ctx: ctx}
	sess := &agentx.Session{Path: sock, Subtree: m.Base, Name: "portitor-config", Handler: h}
	sess.Run(ctx)
}

// snmpState answers from a snapshot of the state, refreshed in the
// background while SNMP asks.
type snmpState struct {
	s   *Server
	m   *mib.MIB
	ctx context.Context

	mu         sync.Mutex
	snap       mib.Snapshot
	at         time.Time
	refreshing bool
	ready      chan struct{} // closed when the first snapshot is there
	once       sync.Once
}

func (h *snmpState) snapshot() mib.Snapshot {
	h.once.Do(func() { h.ready = make(chan struct{}) })
	h.mu.Lock()
	snap, stale := h.snap, time.Since(h.at) > snmpRefresh
	if stale && !h.refreshing {
		h.refreshing = true
		go h.refresh()
	}
	h.mu.Unlock()
	if snap == nil {
		select {
		case <-h.ready:
		case <-time.After(5 * time.Second):
		}
		h.mu.Lock()
		snap = h.snap
		h.mu.Unlock()
	}
	return snap
}

func (h *snmpState) refresh() {
	ctx, cancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer cancel()
	tree, err := h.s.stateTree(ctx, snmpUser)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refreshing = false
	if err != nil {
		slog.Warn("snmp: the state", "err", err)
		return
	}
	first := h.snap == nil
	h.snap, h.at = h.m.Snapshot(tree), time.Now()
	if first {
		close(h.ready)
	}
}

func (h *snmpState) Get(oid agentx.OID) (agentx.Value, bool) {
	return h.snapshot().Get(oid)
}

func (h *snmpState) Next(oid agentx.OID, include bool, end agentx.OID) (agentx.VarBind, bool) {
	return h.snapshot().Next(oid, include, end)
}
