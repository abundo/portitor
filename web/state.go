// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/models"
)

// The state of the YANG modules (portitor-state.yang): the running
// configuration with what the firewalls run and see filled in, from the
// API's live views as the user asks for them. Each view is filtered by
// tenant and merged over the firewalls as the GUI gets it.

// stateTree is the running configuration with the state, for the user u.
func (s *Server) stateTree(ctx context.Context, u *models.User) (*datastore.Tree, error) {
	t, err := s.tree()
	if err != nil {
		return nil, err
	}
	tree, err := t.store.Running(ctx)
	if err != nil {
		return nil, err
	}
	var errs []string
	get := func(path string, into any) bool {
		code, body := s.requestAs(ctx, u, "GET", path, nil)
		if code/100 != 2 {
			if code != 403 {
				errs = append(errs, fmt.Sprintf("%s: %s", path, apiError(body)))
			}
			return false
		}
		if err := json.Unmarshal(body, into); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			return false
		}
		return true
	}
	root := tree.Root
	// state is an instance's state container, the instance made in the
	// state tree when running doesn't have it (yet).
	state := func(name string) *datastore.Node {
		in := root.Entry("instance", []string{name})
		if in == nil {
			in = root.AddEntry(root.S.Child("instance"), map[string]string{"name": name})
		}
		return in.AddContainer(in.S.Child("state"))
	}

	var st agentapi.Status
	if get("/api/agent/status", &st) {
		sys := root.AddContainer(root.S.Child("system"))
		datastore.Fill(sys, st)
		for _, in := range st.Instances {
			n := state(in.Name)
			datastore.FillList(n, "interfaces", in.Interfaces)
			datastore.FillList(n, "routes", in.Routes)
			datastore.FillList(n, "wireguard", in.WireGuard)
			names := make([]string, 0, len(in.Services))
			for name := range in.Services {
				names = append(names, name)
			}
			sort.Strings(names)
			var svcs []map[string]string
			for _, name := range names {
				svcs = append(svcs, map[string]string{"name": name, "state": in.Services[name]})
			}
			datastore.FillList(n, "services", svcs)
		}
	}
	var leases agentapi.LeasesResponse
	if get("/api/agent/leases", &leases) {
		for _, l := range leases.Client {
			if l.Family == "" {
				l.Family = "ipv4"
			}
			datastore.FillList(state(l.Instance), "dhcp-client-leases", []agentapi.Lease{l})
		}
		for inst, ls := range leases.Server {
			datastore.FillList(state(inst), "dhcp-server-leases", ls)
		}
	}
	var nb agentapi.NeighboursResponse
	if get("/api/agent/neighbours", &nb) {
		for _, n := range nb.IP {
			datastore.FillList(state(n.Instance), "ip-neighbours", []agentapi.IPNeighbour{n})
		}
		for _, n := range nb.LLDP {
			datastore.FillList(state(n.Instance), "lldp-neighbours", []agentapi.LLDPNeighbour{n})
		}
	}
	var rc agentapi.RuleCountersResponse
	if get("/api/agent/rule-counters", &rc) {
		// A rule's id is unique over the instances: its instance is the
		// one running it.
		owner := map[string]string{}
		for _, in := range root.Lists["instance"] {
			for _, r := range in.Lists["rule"] {
				owner[r.Leaves["id"]] = in.Leaves["name"]
			}
		}
		ids := make([]uint32, 0, len(rc.Rules))
		for id := range rc.Rules {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			key := strconv.FormatUint(uint64(id), 10)
			if inst, ok := owner[key]; ok {
				c := rc.Rules[id]
				datastore.FillList(state(inst), "rules", []map[string]any{{"id": id, "orig_packets": c.OrigPackets,
					"orig_bytes": c.OrigBytes, "reply_packets": c.ReplyPackets, "reply_bytes": c.ReplyBytes}})
			}
		}
	}
	if s.bgpConfigured(root) {
		var bgp agentapi.BGPResponse
		if get("/api/agent/bgp", &bgp) {
			for _, b := range bgp.Instances {
				b.VRF = stateVRF(b.VRF)
				datastore.FillList(state(b.Instance), "bgp", []agentapi.BGPInstance{b})
			}
		}
	}
	// The routing protocols and services, each asked for only when the
	// running configuration has it (asking FRR or chronyd takes time).
	if anyInstance(root, func(in *datastore.Node) bool { return anyEntry(in, "ospf", "enabled", "true") }) {
		var r agentapi.OSPFResponse
		if get("/api/agent/ospf", &r) {
			for _, o := range r.Instances {
				for version, v := range map[string]*agentapi.OSPFState{"2": o.V2, "3": o.V3} {
					if v == nil {
						continue
					}
					datastore.FillList(state(o.Instance), "ospf", []any{withKeys(v, map[string]any{"version": version, "vrf": stateVRF(o.VRF)})})
				}
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return anyEntry(in, "isis", "enabled", "true") }) {
		var r agentapi.ISISResponse
		if get("/api/agent/isis", &r) {
			for _, i := range r.Instances {
				i.VRF = stateVRF(i.VRF)
				datastore.FillList(state(i.Instance), "isis", []agentapi.ISISInstance{i})
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return len(in.Lists["vrrp-router"]) > 0 }) {
		var r agentapi.VRRPResponse
		if get("/api/agent/vrrp", &r) {
			for _, v := range r.Instances {
				n := state(v.Instance)
				datastore.Fill(n.AddContainer(n.S.Child("vrrp")), v)
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return len(in.Lists["bfd-interface"]) > 0 }) {
		var r agentapi.BFDResponse
		if get("/api/agent/bfd", &r) {
			for _, b := range r.Instances {
				n := state(b.Instance)
				datastore.Fill(n.AddContainer(n.S.Child("bfd")), b)
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return in.Leaves["ntp-enabled"] == "true" }) {
		var r agentapi.NTPResponse
		if get("/api/agent/ntp", &r) {
			for _, x := range r.Instances {
				n := state(x.Instance)
				datastore.Fill(n.AddContainer(n.S.Child("ntp")), x)
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return in.Leaves["nat64"] == "true" }) {
		var r agentapi.NAT64Response
		if get("/api/agent/nat64", &r) {
			for _, x := range r.Instances {
				n := state(x.Instance)
				datastore.Fill(n.AddContainer(n.S.Child("nat64")), x)
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return anyEntry(in, "interface", "kind", "openvpn") }) {
		var r agentapi.OpenVPNResponse
		if get("/api/agent/openvpn", &r) {
			for _, x := range r.Servers {
				datastore.FillList(state(x.Instance), "openvpn", []agentapi.OpenVPNServer{x})
			}
		}
	}
	if anyInstance(root, func(in *datastore.Node) bool { return len(in.Lists["rate-limit"]) > 0 }) {
		var r agentapi.RateLimitsResponse
		if get("/api/agent/rate-limits", &r) {
			for inst, limits := range r.Instances {
				names := make([]string, 0, len(limits))
				for name := range limits {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					datastore.FillList(state(inst), "rate-limits", []any{withKeys(limits[name], map[string]any{"name": name})})
				}
			}
		}
	}
	if len(errs) > 0 {
		sys := root.AddContainer(root.S.Child("system"))
		sys.LeafLists["errors"] = errs
	}
	return tree, nil
}

// anyInstance reports whether an instance of the running configuration
// is so.
func anyInstance(root *datastore.Node, fn func(*datastore.Node) bool) bool {
	for _, in := range root.Lists["instance"] {
		if fn(in) {
			return true
		}
	}
	return false
}

// anyEntry reports whether an entry of the list of in has the leaf at
// value.
func anyEntry(in *datastore.Node, list, leaf, value string) bool {
	for _, e := range in.Lists[list] {
		if e.Leaf(leaf) == value {
			return true
		}
	}
	return false
}

// stateVRF is the state's name of a VRF: main for the main table.
func stateVRF(vrf string) string {
	if vrf == "" {
		return "main"
	}
	return vrf
}

// withKeys is v as a JSON object with the keys added, for an entry whose
// keys the API has outside it.
func withKeys(v any, keys map[string]any) map[string]any {
	out := map[string]any{}
	if data, err := json.Marshal(v); err == nil {
		_ = json.Unmarshal(data, &out)
	}
	for k, x := range keys {
		out[k] = x
	}
	return out
}

// bgpConfigured reports whether a running instance has BGP, so that
// state asks FRR only then.
func (s *Server) bgpConfigured(root *datastore.Node) bool {
	for _, in := range root.Lists["instance"] {
		for _, b := range in.Lists["bgp"] {
			if b.Leaves["enabled"] == "true" {
				return true
			}
		}
	}
	return false
}
