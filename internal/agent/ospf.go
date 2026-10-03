// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/abundo/portitor/internal/agentapi"
)

// OSPF asks FRR, through vtysh, for the OSPFv2 and OSPFv3 state of each
// instance that runs them: areas, interfaces, neighbours and routes.
func (a *Agent) OSPF(ctx context.Context) *agentapi.OSPFResponse {
	resp := &agentapi.OSPFResponse{Instances: []agentapi.OSPFInstance{}}
	a.mu.Lock()
	doc := a.applied
	a.mu.Unlock()
	if doc == nil {
		return resp
	}
	for i := range doc.Instances {
		in := &doc.Instances[i]
		if !in.OSPFRunning(2) && !in.OSPFRunning(3) {
			continue
		}
		oi := agentapi.OSPFInstance{Instance: in.Name}
		vtysh := a.vtysh(ctx, in)
		if in.OSPFRunning(2) {
			oi.V2 = ospfState(vtysh, 2)
		}
		if in.OSPFRunning(3) {
			oi.V3 = ospfState(vtysh, 3)
		}
		resp.Instances = append(resp.Instances, oi)
	}
	return resp
}

// ospfState gathers one OSPF version's state with vtysh. FRR's JSON
// differs between versions, so the parsers read it loosely (jsonObj).
func ospfState(vtysh func(string) ([]byte, error), version int) *agentapi.OSPFState {
	cmd := "show ip ospf"
	if version == 3 {
		cmd = "show ipv6 ospf6"
	}
	st := &agentapi.OSPFState{
		Areas: []agentapi.OSPFAreaInfo{}, Interfaces: []agentapi.OSPFInterfaceInfo{},
		Neighbors: []agentapi.OSPFNeighborInfo{}, Routes: []agentapi.OSPFRoute{},
	}
	out, err := vtysh(cmd + " json")
	if err != nil {
		st.Error = vtyshError(out, err)
		return st
	}
	router, err := parseJSONObj(out)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.RouterID = router.str("routerId")
	if out, err := vtysh(cmd + " interface json"); err == nil {
		st.Interfaces = parseOSPFInterfaces(out, version)
	}
	if out, err := vtysh(cmd + " neighbor json"); err == nil {
		st.Neighbors = parseOSPFNeighbors(out, version)
	}
	st.Areas = ospfAreas(router, st.Interfaces, st.Neighbors)
	if out, err := vtysh(cmd + " route json"); err == nil {
		st.Routes = parseOSPFRoutes(out)
		if len(st.Routes) > agentapi.OSPFMaxRoutes {
			st.Routes, st.RoutesTruncated = st.Routes[:agentapi.OSPFMaxRoutes], true
		}
	}
	return st
}

// jsonObj is a JSON object read without a fixed shape.
type jsonObj map[string]any

func parseJSONObj(data []byte) (jsonObj, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unexpected answer from vtysh: %v", err)
	}
	return m, nil
}

// str returns the first of keys that is a string.
func (o jsonObj) str(keys ...string) string {
	for _, k := range keys {
		if s, ok := o[k].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// num returns the first of keys that is a number.
func (o jsonObj) num(keys ...string) (int64, bool) {
	for _, k := range keys {
		if n, ok := o[k].(float64); ok {
			return int64(n), true
		}
	}
	return 0, false
}

func (o jsonObj) flag(key string) bool {
	b, _ := o[key].(bool)
	return b
}

func (o jsonObj) obj(key string) jsonObj {
	m, _ := o[key].(map[string]any)
	return m
}

func (o jsonObj) list(key string) []jsonObj {
	l, _ := o[key].([]any)
	var out []jsonObj
	for _, x := range l {
		if m, ok := x.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// objects returns the values of o that are objects, by key.
func (o jsonObj) objects() map[string]jsonObj {
	out := map[string]jsonObj{}
	for k, v := range o {
		if m, ok := v.(map[string]any); ok {
			out[k] = m
		}
	}
	return out
}

// areaID drops what FRR may write after an area id ("0.0.0.1 [Stub]").
func areaID(s string) string {
	if i := strings.IndexByte(s, ' '); i > 0 {
		return s[:i]
	}
	return s
}

// parseOSPFInterfaces reads `show ip ospf interface json` or `show ipv6
// ospf6 interface json`: interfaces by name, under "interfaces" or not.
func parseOSPFInterfaces(data []byte, version int) []agentapi.OSPFInterfaceInfo {
	root, err := parseJSONObj(data)
	if err != nil {
		return []agentapi.OSPFInterfaceInfo{}
	}
	ifs := root.obj("interfaces")
	if ifs == nil {
		ifs = root
	}
	out := []agentapi.OSPFInterfaceInfo{}
	for name, x := range ifs.objects() {
		// Interfaces without OSPF are listed too.
		area := areaID(x.str("area", "areaId"))
		if area == "" || x["ospfEnabled"] == false || x["attachedToArea"] == false {
			continue
		}
		ifc := agentapi.OSPFInterfaceInfo{
			Name:        name,
			Area:        area,
			State:       x.str("state"),
			NetworkType: x.str("networkType", "type"),
			Passive:     x.flag("timerPassiveIface") || x.flag("passive"),
			DR:          x.str("drId", "dr"),
			BDR:         x.str("bdrId", "bdr"),
		}
		ifc.Cost, _ = x.num("cost")
		ifc.Priority, _ = x.num("priority")
		ifc.Neighbors, _ = x.num("nbrCount")
		ifc.Adjacent, _ = x.num("nbrAdjacentCount")
		if a := x.str("ipAddress"); a != "" {
			ifc.Address = a
			if l, ok := x.num("ipAddressPrefixlen"); ok {
				ifc.Address = fmt.Sprintf("%s/%d", a, l)
			}
		}
		if version == 3 {
			for _, a := range x.list("internetAddress") {
				if addr := a.str("address"); addr != "" && !strings.HasPrefix(addr, "fe80") {
					ifc.Address = addr
					break
				}
			}
		}
		out = append(out, ifc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// parseOSPFNeighbors reads `show ip ospf neighbor json` (neighbours by
// router id, each a list in FRR 8 and later) or `show ipv6 ospf6 neighbor
// json` (a list).
func parseOSPFNeighbors(data []byte, version int) []agentapi.OSPFNeighborInfo {
	root, err := parseJSONObj(data)
	out := []agentapi.OSPFNeighborInfo{}
	if err != nil {
		return out
	}
	add := func(id string, x jsonObj) {
		n := agentapi.OSPFNeighborInfo{
			RouterID:  x.str("neighborId", "routerId"),
			Address:   x.str("ifaceAddress", "address"),
			Interface: x.str("ifaceName", "interfaceName"),
			Uptime:    x.str("upTime", "duration"),
			DeadTime:  x.str("deadTime", "routerDeadIntervalTimerDueMsec"),
		}
		if n.RouterID == "" {
			n.RouterID = id
		}
		n.Priority, _ = x.num("nbrPriority", "priority")
		// ospfd: "Full/DR" (nbrState, state); ospf6d: state and ifState.
		state := x.str("nbrState", "state")
		n.State, n.Role, _ = strings.Cut(state, "/")
		if c := x.str("converged"); c != "" {
			n.State = c
		}
		if r := x.str("role", "ifState"); r != "" {
			n.Role = r
		}
		// ospfd names the interface with its address: eth0:10.0.0.1.
		n.Interface, _, _ = strings.Cut(n.Interface, ":")
		if d, ok := x["deadTime"].(float64); ok {
			n.DeadTime = fmt.Sprintf("%.0fs", d/1000)
		}
		out = append(out, n)
	}
	if version == 3 {
		for _, x := range root.list("neighbors") {
			add("", x)
		}
	} else {
		nbrs := root.obj("neighbors")
		if nbrs == nil {
			nbrs = root
		}
		for id, v := range nbrs {
			switch v := v.(type) {
			case []any:
				for _, x := range v {
					if m, ok := x.(map[string]any); ok {
						add(id, m)
					}
				}
			case map[string]any:
				add(id, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RouterID != out[j].RouterID {
			return out[i].RouterID < out[j].RouterID
		}
		return out[i].Interface < out[j].Interface
	})
	return out
}

// ospfAreas reads the areas of `show ip ospf json` or `show ipv6 ospf6
// json`, counting from the interfaces and neighbours what FRR leaves out.
func ospfAreas(router jsonObj, ifs []agentapi.OSPFInterfaceInfo, nbrs []agentapi.OSPFNeighborInfo) []agentapi.OSPFAreaInfo {
	ifArea := map[string]string{}
	for _, ifc := range ifs {
		ifArea[ifc.Name] = ifc.Area
	}
	out := []agentapi.OSPFAreaInfo{}
	for id, x := range router.obj("areas").objects() {
		a := agentapi.OSPFAreaInfo{ID: areaID(id)}
		switch {
		case x.flag("nssa"):
			a.Type = "nssa"
		case x["stubNoSummary"] != nil || x.flag("stub"):
			a.Type = "stub"
		}
		if n, ok := x.num("areaIfTotalCounter"); ok {
			a.Interfaces = int(n)
		} else {
			for _, area := range ifArea {
				if area == a.ID {
					a.Interfaces++
				}
			}
		}
		if n, ok := x.num("nbrFullAdjacentCounter"); ok {
			a.FullAdjacencies = int(n)
		} else {
			for _, n := range nbrs {
				if n.State == "Full" && ifArea[n.Interface] == a.ID {
					a.FullAdjacencies++
				}
			}
		}
		n, _ := x.num("lsaNumber", "numberOfAreaScopedLsa")
		a.LSAs = int(n)
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ospfRouteTypes reads ospfd's route types (N, N IA, N E2) and ospf6d's
// path types (IA intra-area, IE inter-area, E1, E2).
var ospfRouteTypes = map[string]string{
	"N": "intra-area", "N IA": "inter-area", "N E1": "external 1", "N E2": "external 2",
	"IA": "intra-area", "IE": "inter-area", "E1": "external 1", "E2": "external 2",
}

// parseOSPFRoutes reads `show ip ospf route json` (routes, and routers,
// by prefix or router id) or `show ipv6 ospf6 route json` (under
// "routes").
func parseOSPFRoutes(data []byte) []agentapi.OSPFRoute {
	root, err := parseJSONObj(data)
	out := []agentapi.OSPFRoute{}
	if err != nil {
		return out
	}
	entries := root.objects()
	if r := root.obj("routes"); r != nil {
		entries = r.objects()
	}
	for _, key := range []string{"networks", "externalRoutes"} {
		for k, v := range root.obj(key).objects() {
			entries[k] = v
		}
	}
	for prefix, x := range entries {
		// Routes to routers (ABRs, ASBRs) are keyed by router id.
		if _, err := netip.ParsePrefix(prefix); err != nil {
			continue
		}
		typ := x.str("routeType", "pathType")
		r := agentapi.OSPFRoute{Prefix: prefix, Type: typ, Area: areaID(x.str("area")), NextHops: []string{}}
		if t, ok := ospfRouteTypes[typ]; ok {
			r.Type = t
		}
		if c, ok := x.num("cost", "metricCost"); ok {
			r.Cost = &c
		}
		for _, nh := range append(x.list("nexthops"), x.list("nextHops")...) {
			ip := nh.str("ip", "nextHop")
			switch ip {
			case "", "::", "0.0.0.0":
				ip = "directly attached"
			}
			r.NextHops = append(r.NextHops, ip)
			if ifc := nh.str("via", "directlyAttachedTo", "interfaceName"); ifc != "" {
				r.Interface = append(r.Interface, ifc)
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}
