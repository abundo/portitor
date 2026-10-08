// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/abundo/portitor/internal/agentapi"
)

// ISIS asks FRR, through vtysh, for the IS-IS state of each instance that
// runs it: adjacencies, interfaces and routes.
func (a *Agent) ISIS(ctx context.Context) *agentapi.ISISResponse {
	resp := &agentapi.ISISResponse{Instances: []agentapi.ISISInstance{}}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		if !in.ISISRunning() {
			continue
		}
		resp.Instances = append(resp.Instances, isisInstance(in.Name, a.vtysh(ctx, in)))
	}
	return resp
}

// isisInstance gathers one instance's IS-IS state with vtysh. FRR's JSON
// has areas holding circuits (show isis neighbor/interface) or levels
// (show isis route), and has changed between releases, so the parsers
// walk it loosely.
func isisInstance(name string, vtysh func(string) ([]byte, error)) agentapi.ISISInstance {
	st := agentapi.ISISInstance{
		Instance: name, Neighbors: []agentapi.ISISNeighborInfo{},
		Interfaces: []agentapi.ISISInterfaceInfo{}, Routes: []agentapi.ISISRoute{},
	}
	out, err := vtysh("show isis summary json")
	if err != nil {
		st.Error = vtyshError(out, err)
		return st
	}
	if sum, err := parseJSONObj(out); err == nil {
		st.SystemID = findString(sum, "system-id", "sysid", "systemId")
	}
	if out, err := vtysh("show isis neighbor json"); err == nil {
		st.Neighbors = parseISISNeighbors(out)
	}
	if out, err := vtysh("show isis interface json"); err == nil {
		st.Interfaces = parseISISInterfaces(out)
	}
	if out, err := vtysh("show isis route json"); err == nil {
		st.Routes = parseISISRoutes(out)
		if len(st.Routes) > agentapi.ISISMaxRoutes {
			st.Routes, st.RoutesTruncated = st.Routes[:agentapi.ISISMaxRoutes], true
		}
	}
	return st
}

// findString returns the first string under one of keys, at any depth.
func findString(v any, keys ...string) string {
	switch v := v.(type) {
	case jsonObj:
		return findString(map[string]any(v), keys...)
	case map[string]any:
		if s := jsonObj(v).str(keys...); s != "" {
			return s
		}
		for _, x := range v {
			if s := findString(x, keys...); s != "" {
				return s
			}
		}
	case []any:
		for _, x := range v {
			if s := findString(x, keys...); s != "" {
				return s
			}
		}
	}
	return ""
}

// isisCircuits returns the circuits of every area: {"areas": [{"area":
// tag, "circuits": [...]}]}.
func isisCircuits(data []byte) []jsonObj {
	root, err := parseJSONObj(data)
	if err != nil {
		return nil
	}
	var out []jsonObj
	for _, area := range root.list("areas") {
		out = append(out, area.list("circuits")...)
	}
	return out
}

// isisLevel writes a level number (1, 2, 3 for both) as FRR shows it.
func isisLevel(x jsonObj, keys ...string) string {
	if n, ok := x.num(keys...); ok {
		switch n {
		case 1:
			return "L1"
		case 2:
			return "L2"
		case 3:
			return "L1L2"
		}
		return fmt.Sprint(n)
	}
	return x.str(keys...)
}

// parseISISNeighbors reads `show isis neighbor json`: a circuit per
// adjacency, the neighbour under "adj" (its hostname, or system id).
func parseISISNeighbors(data []byte) []agentapi.ISISNeighborInfo {
	out := []agentapi.ISISNeighborInfo{}
	for _, c := range isisCircuits(data) {
		id := c.str("adj", "system-id", "systemId")
		if id == "" {
			continue
		}
		ifc := c.str("interface")
		if o := c.obj("interface"); o != nil {
			ifc = o.str("name")
		}
		out = append(out, agentapi.ISISNeighborInfo{
			SystemID:  id,
			Interface: ifc,
			Level:     isisLevel(c, "level"),
			State:     c.str("state"),
			HoldTime:  c.str("expires-in", "holdtime", "hold-time"),
			SNPA:      c.str("snpa"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SystemID != out[j].SystemID {
			return out[i].SystemID < out[j].SystemID
		}
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Level < out[j].Level
	})
	return out
}

// parseISISInterfaces reads `show isis interface json`: a circuit per
// interface, its details under "interface".
func parseISISInterfaces(data []byte) []agentapi.ISISInterfaceInfo {
	out := []agentapi.ISISInterfaceInfo{}
	for _, c := range isisCircuits(data) {
		x := c.obj("interface")
		if x == nil {
			x = c
		}
		name := x.str("name", "interface")
		if name == "" {
			continue
		}
		out = append(out, agentapi.ISISInterfaceInfo{
			Name:  name,
			State: x.str("state"),
			Type:  x.str("type", "circuit-type"),
			Level: isisLevel(x, "level", "is-type"),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parseISISRoutes reads `show isis route json`: rows of FRR's tables
// (Prefix, Metric, Interface, Nexthop) under the levels of each area. A
// route with several next hops has rows without a prefix after its first.
func parseISISRoutes(data []byte) []agentapi.ISISRoute {
	root, err := parseJSONObj(data)
	out := []agentapi.ISISRoute{}
	if err != nil {
		return out
	}
	var walk func(v any, level string)
	walk = func(v any, level string) {
		switch v := v.(type) {
		case []any:
			for _, x := range v {
				walk(x, level)
			}
		case map[string]any:
			x := jsonObj(v)
			if l := isisLevel(x, "id", "level"); l != "" && x["Prefix"] == nil && x["prefix"] == nil {
				level = l
			}
			if _, isRow := v["Prefix"]; isRow || v["prefix"] != nil {
				prefix := x.str("Prefix", "prefix")
				nh := x.str("Nexthop", "nexthop", "Next-Hop")
				ifc := x.str("Interface", "interface")
				if prefix == "" {
					// Another next hop of the route above.
					if len(out) > 0 {
						r := &out[len(out)-1]
						r.NextHops = appendHop(r.NextHops, nh)
						r.Interface = appendHop(r.Interface, ifc)
					}
					return
				}
				if _, err := netip.ParsePrefix(prefix); err != nil {
					return
				}
				r := agentapi.ISISRoute{Prefix: prefix, Level: level, NextHops: appendHop([]string{}, nh), Interface: appendHop(nil, ifc)}
				if m, ok := x.num("Metric", "metric"); ok {
					r.Metric = &m
				} else if s := x.str("Metric", "metric"); s != "" {
					var m int64
					if _, err := fmt.Sscan(s, &m); err == nil {
						r.Metric = &m
					}
				}
				out = append(out, r)
				return
			}
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(v[k], level)
			}
		}
	}
	walk(map[string]any(root), "")
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].Level < out[j].Level
	})
	return out
}

func appendHop(l []string, s string) []string {
	s = strings.TrimSpace(s)
	switch s {
	case "":
		return l
	case "-":
		s = "directly attached"
	}
	return append(l, s)
}
