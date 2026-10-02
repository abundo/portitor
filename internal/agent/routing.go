// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"

	"github.com/abundo/portitor/internal/agentapi"
)

type RouteEntry = agentapi.RouteEntry

// RoutingTable lists, for each instance of the applied document, the IPv4
// and IPv6 routes of its main table that go out its interfaces.
func (a *Agent) RoutingTable(ctx context.Context) *agentapi.RoutingTableResponse {
	resp := &agentapi.RoutingTableResponse{Routes: []RouteEntry{}}
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
			out, err := a.bg.Run(ctx, in.NetnsName(), "ip", "-j", fam, "route", "show")
			if err != nil {
				continue
			}
			for _, r := range parseIPRoute(out, fam == "-6") {
				// The default instance shares the root namespace with
				// interfaces that are not the firewall's (docker, ...).
				if r.Interface == "" || ifaces[r.Interface] {
					r.Instance = in.Name
					resp.Routes = append(resp.Routes, r)
				}
			}
		}
	}
	return resp
}

// parseIPRoute reads `ip -j route show`.
func parseIPRoute(data []byte, v6 bool) []RouteEntry {
	var entries []struct {
		Type     string `json:"type"`
		Dst      string `json:"dst"`
		Gateway  string `json:"gateway"`
		Dev      string `json:"dev"`
		Protocol string `json:"protocol"`
		Scope    string `json:"scope"`
		PrefSrc  string `json:"prefsrc"`
		Metric   int    `json:"metric"`
		Nexthops []struct {
			Gateway string `json:"gateway"`
			Dev     string `json:"dev"`
		} `json:"nexthops"`
	}
	if len(data) == 0 || json.Unmarshal(data, &entries) != nil {
		return nil
	}
	fam := "ipv4"
	if v6 {
		fam = "ipv6"
	}
	var out []RouteEntry
	for _, e := range entries {
		r := RouteEntry{
			Family:      fam,
			Type:        e.Type,
			Destination: e.Dst,
			Gateway:     e.Gateway,
			Interface:   e.Dev,
			Protocol:    e.Protocol,
			Scope:       e.Scope,
			Source:      e.PrefSrc,
			Metric:      e.Metric,
		}
		if r.Type == "" {
			r.Type = "unicast"
		}
		// A multipath route: one entry per next hop.
		if len(e.Nexthops) > 0 {
			for _, nh := range e.Nexthops {
				r.Gateway, r.Interface = nh.Gateway, nh.Dev
				out = append(out, r)
			}
			continue
		}
		if r.Destination == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}
