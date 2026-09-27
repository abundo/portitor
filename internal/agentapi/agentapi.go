// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agentapi is the wire format of portitor-agent's management API,
// shared by the agent and its client in portitor-web.
package agentapi

import (
	"time"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

type ApplyRequest struct {
	Document fwconfig.Document `json:"document"`
	// ConfirmTimeoutSeconds > 0 rolls the change back unless confirmed.
	ConfirmTimeoutSeconds int `json:"confirm_timeout_seconds"`
}

type RenderRequest struct {
	Document fwconfig.Document `json:"document"`
}

type ConfirmRequest struct {
	Generation int64 `json:"generation"`
}

type LeasesResponse struct {
	Client []Lease                  `json:"client"`
	Server map[string][]ServerLease `json:"server"`
}

type ErrorResponse struct {
	Error    string   `json:"error"`
	Problems []string `json:"problems,omitempty"`
}

type Status struct {
	Hostname   string           `json:"hostname"`
	Version    string           `json:"version"`
	DryRun     bool             `json:"dry_run"`
	Generation int64            `json:"generation"`
	LastApply  *time.Time       `json:"last_apply,omitempty"`
	LastError  string           `json:"last_error,omitempty"`
	Pending    *PendingStatus   `json:"pending,omitempty"`
	Instances  []InstanceStatus `json:"instances"`
	DHCPLeases []Lease          `json:"dhcp_client_leases"`
}

type PendingStatus struct {
	Generation int64     `json:"generation"`
	Deadline   time.Time `json:"deadline"`
}

type InstanceStatus struct {
	Name       string            `json:"name"`
	Netns      string            `json:"netns,omitempty"`
	Interfaces []IfaceStatus     `json:"interfaces"`
	Routes     []RouteStatus     `json:"routes"`
	WireGuard  []WGStatus        `json:"wireguard"`
	Services   map[string]string `json:"services"`
}

type IfaceStatus struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind,omitempty"`
	State     string   `json:"state"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac,omitempty"`
	Addresses []string `json:"addresses"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
}

type RouteStatus struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway,omitempty"`
	Dev      string `json:"dev,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

type WGStatus struct {
	Interface  string         `json:"interface"`
	PublicKey  string         `json:"public_key"`
	ListenPort int            `json:"listen_port"`
	Peers      []WGPeerStatus `json:"peers"`
}

type WGPeerStatus struct {
	PublicKey       string     `json:"public_key"`
	Endpoint        string     `json:"endpoint,omitempty"`
	AllowedIPs      []string   `json:"allowed_ips"`
	LatestHandshake *time.Time `json:"latest_handshake,omitempty"`
	RxBytes         uint64     `json:"rx_bytes"`
	TxBytes         uint64     `json:"tx_bytes"`
}

// ServerLease is an active lease handed out by Kea.
type ServerLease struct {
	Address  string    `json:"address"`
	MAC      string    `json:"mac"`
	Hostname string    `json:"hostname,omitempty"`
	Expires  time.Time `json:"expires"`
}

// Lease is what the DHCP client learned on one interface.
type Lease struct {
	Instance   string    `json:"instance"`
	Interface  string    `json:"interface"`
	Address    string    `json:"address"` // CIDR
	Router     string    `json:"router,omitempty"`
	DNS        []string  `json:"dns,omitempty"`
	Server     string    `json:"server,omitempty"`
	Obtained   time.Time `json:"obtained"`
	Expires    time.Time `json:"expires"`
	State      string    `json:"state"` // requesting, bound, error
	LastError  string    `json:"last_error,omitempty"`
	RenewAfter time.Time `json:"renew_after"`
}

// RenderResult is a preview: the files a document would produce next to
// the files currently applied.
type RenderResult struct {
	Files   []render.File `json:"files"`
	Current []render.File `json:"current"`
}

type ApplyResult struct {
	Generation     int64      `json:"generation"`
	Log            []string   `json:"log"`
	ConfirmBy      *time.Time `json:"confirm_by,omitempty"`
	RolledBack     bool       `json:"rolled_back,omitempty"`
	RollbackErrors string     `json:"rollback_error,omitempty"`
}
