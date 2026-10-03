// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// errStopping cancels a DHCP client when the agent stops. Unlike a client
// whose interface left the config, it keeps its lease: the address, route
// and delegated prefix stay, and so does the saved lease, which the next
// start renews. Restarting the agent (an update) does not drop the uplink.
var errStopping = errors.New("agent stopping")

// savedLease is a lease as the server sent it, kept under
// <state_dir>/dhcp4 or dhcp6 in <instance>/<interface>.json.
type savedLease struct {
	Offer    []byte    `json:"offer,omitempty"` // DHCPv4
	ACK      []byte    `json:"ack,omitempty"`   // DHCPv4
	Reply    []byte    `json:"reply,omitempty"` // DHCPv6
	Obtained time.Time `json:"obtained"`
}

// leaseID is a saved lease's instance and interface.
type leaseID struct{ instance, iface string }

func leasePath(dir string, id leaseID) string {
	return filepath.Join(dir, id.instance, id.iface+".json")
}

func saveLease(dir string, id leaseID, s savedLease) {
	if dir == "" {
		return
	}
	if err := writeJSON(leasePath(dir, id), s, 0o600); err != nil {
		slog.Warn("save dhcp lease", "instance", id.instance, "interface", id.iface, "err", err)
	}
}

func dropLease(dir string, id leaseID) {
	if dir == "" {
		return
	}
	if err := os.Remove(leasePath(dir, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("remove dhcp lease", "instance", id.instance, "interface", id.iface, "err", err)
	}
}

// savedLeases reads every lease saved in dir.
func savedLeases(dir string) map[leaseID]savedLease {
	out := map[leaseID]savedLease{}
	if dir == "" {
		return out
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*.json"))
	for _, f := range files {
		var s savedLease
		if err := readJSON(f, &s); err != nil {
			slog.Warn("read dhcp lease", "file", f, "err", err)
			continue
		}
		id := leaseID{filepath.Base(filepath.Dir(f)), strings.TrimSuffix(filepath.Base(f), ".json")}
		out[id] = s
	}
	return out
}
