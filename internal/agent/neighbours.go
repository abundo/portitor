// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/abundo/portitor/internal/agentapi"
)

type IPNeighbour = agentapi.IPNeighbour

// Neighbours lists, for each instance of the applied document, the ARP and
// ND entries of its interfaces and the LLDP neighbours heard on them.
func (a *Agent) Neighbours(ctx context.Context) *agentapi.NeighboursResponse {
	resp := &agentapi.NeighboursResponse{IP: []IPNeighbour{}}
	resp.LLDPPorts, resp.LLDP = a.lldp.Snapshot()
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for _, in := range doc.Instances {
		ifaces := map[string]bool{}
		for _, ifc := range in.Interfaces {
			ifaces[ifc.Name] = true
		}
		for _, fam := range []string{"-4", "-6"} {
			out, err := a.bg.Run(ctx, in.NetnsName(), "ip", "-j", fam, "neigh", "show")
			if err != nil {
				continue
			}
			for _, n := range parseIPNeigh(out, fam == "-6") {
				// The default instance shares the root namespace with
				// interfaces that are not the firewall's (docker, ...).
				if ifaces[n.Interface] {
					n.Instance = in.Name
					resp.IP = append(resp.IP, n)
				}
			}
		}
	}
	return resp
}

// parseIPNeigh reads `ip -j neigh show`. "router" is a key with a null
// value when the neighbour is a router.
func parseIPNeigh(data []byte, v6 bool) []IPNeighbour {
	var entries []map[string]json.RawMessage
	if len(data) == 0 || json.Unmarshal(data, &entries) != nil {
		return nil
	}
	fam := "ipv4"
	if v6 {
		fam = "ipv6"
	}
	str := func(m map[string]json.RawMessage, k string) string {
		var s string
		_ = json.Unmarshal(m[k], &s)
		return s
	}
	var out []IPNeighbour
	for _, e := range entries {
		var states []string
		_ = json.Unmarshal(e["state"], &states)
		_, router := e["router"]
		n := IPNeighbour{
			Interface: str(e, "dev"),
			Family:    fam,
			Address:   str(e, "dst"),
			MAC:       str(e, "lladdr"),
			State:     strings.ToLower(strings.Join(states, " ")),
			Router:    router,
		}
		if n.Address == "" || n.Interface == "" {
			continue
		}
		out = append(out, n)
	}
	return out
}
