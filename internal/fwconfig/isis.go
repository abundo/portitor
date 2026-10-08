// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"regexp"
	"strings"
)

// ISIS runs FRR's isisd, with zebra, in the instance: one IS-IS process
// (ISISTag) for IPv4 and IPv6. IS-IS is not IP (its PDUs are LLC frames on
// the link), so nftables' inet tables never see it and it needs no auto
// rules.
type ISIS struct {
	// Enabled runs isisd; off, it is not started (the default).
	Enabled bool `json:"enabled"`
	// NET is the network entity title: area, system id and NSEL 00
	// (49.0001.1921.6800.1001.00), lower case (ParseISISNet).
	NET string `json:"net"`
	// Level is the router's: ISISLevel1, ISISLevel12 or ISISLevel2 ("" is
	// ISISLevel12, FRR's).
	Level string `json:"level,omitempty"`
	// MetricStyle: "" (wide), narrow or transition.
	MetricStyle         string `json:"metric_style,omitempty"`
	LogAdjacencyChanges bool   `json:"log_adjacency_changes,omitempty"`
	// IPv6Topology runs IPv6 in a topology of its own (multi-topology,
	// RFC 5120), so a link may carry one version and not the other.
	IPv6Topology bool `json:"ipv6_topology,omitempty"`
	// Overload (the overload bit) keeps the other routers from routing
	// through this one.
	Overload bool `json:"overload,omitempty"`
	// DefaultOriginate announces a default route into a level.
	DefaultOriginate []ISISDefault      `json:"default_originate,omitempty"`
	Redistribute     []ISISRedistribute `json:"redistribute,omitempty"`
	Interfaces       []ISISInterface    `json:"interfaces,omitempty"`
}

// ISISTag is the area tag of the instance's IS-IS process in frr.conf.
const ISISTag = "portitor"

// IS-IS levels: of the router (ISIS.Level) and of an interface's circuit
// (ISISInterface.CircuitType).
const (
	ISISLevel1  = "level-1"
	ISISLevel12 = "level-1-2"
	ISISLevel2  = "level-2-only"
)

// ISIS metric styles.
const (
	ISISMetricWide       = "wide"
	ISISMetricNarrow     = "narrow"
	ISISMetricTransition = "transition"
)

// ISISDefault announces a default route of Family ("ipv4", "ipv6") into
// Level ("level-1", "level-2"), while the routing table has one, or
// Always.
type ISISDefault struct {
	Family   string `json:"family"`
	Level    string `json:"level"`
	Always   bool   `json:"always,omitempty"`
	RouteMap string `json:"route_map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

// ISISRedistribute redistributes a source's routes of Family into Level,
// with Metric (0: FRR's).
type ISISRedistribute struct {
	Family   string `json:"family"`
	Source   string `json:"source"` // RedistConnected, RedistStatic, RedistBGP, RedistOSPF
	Level    string `json:"level"`
	RouteMap string `json:"route_map,omitempty"`
	Metric   int    `json:"metric,omitempty"`
}

// ISISRedistSources are what IS-IS redistributes. RedistOSPF is OSPFv2's
// routes into IPv4, OSPFv3's into IPv6.
var ISISRedistSources = []string{RedistConnected, RedistStatic, RedistBGP, RedistOSPF}

// ISISInterface is IS-IS on an interface of the instance (by name), for
// its IPv4 or IPv6 networks or both.
type ISISInterface struct {
	Name string `json:"name"`
	IPv4 bool   `json:"ipv4,omitempty"`
	IPv6 bool   `json:"ipv6,omitempty"`
	// CircuitType limits the levels of the adjacencies ("": the router's).
	CircuitType string `json:"circuit_type,omitempty"`
	// PointToPoint skips the DIS election (links, tunnels).
	PointToPoint bool `json:"point_to_point,omitempty"`
	// Passive announces the interface's networks but sends no hellos.
	Passive bool `json:"passive,omitempty"`
	// Metric 0 keeps FRR's (10); intervals 0 keep FRR's (3 s, 10 hellos).
	Metric          int `json:"metric,omitempty"`
	HelloInterval   int `json:"hello_interval,omitempty"`
	HelloMultiplier int `json:"hello_multiplier,omitempty"`
	// Priority in the DIS election; nil keeps FRR's (64).
	Priority *int `json:"priority,omitempty"`
	// BFD watches the neighbours on the interface with BFD, when the
	// interface has it.
	BFD bool `json:"bfd,omitempty"`
}

// isisNetRe: an AFI byte, 0-12 more area bytes in groups of two, a 6-byte
// system id and NSEL 00.
var isisNetRe = regexp.MustCompile(`^[0-9a-f]{2}(\.[0-9a-f]{4}){0,6}(\.[0-9a-f]{4}){3}\.00$`)

// ParseISISNet reads a NET and returns it in lower case.
func ParseISISNet(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	return s, isisNetRe.MatchString(s)
}

// ISISLayer3 reports whether an interface kind carries IP alone (a
// WireGuard or 6in4 tunnel): IS-IS, sent as LLC frames, can only announce
// its networks there (passive).
func ISISLayer3(kind string) bool { return kind == KindWireGuard || kind == Kind6in4 }

// ISISMaxMetric is the highest metric of a metric style.
func ISISMaxMetric(style string) int {
	if style == ISISMetricNarrow {
		return 63
	}
	return 16777215
}

// CheckISIS checks an IS-IS configuration on its own: without its
// references to interfaces and route maps.
func CheckISIS(s *ISIS) []string {
	v := &validator{}
	v.isis("isis", s, nil, nil)
	return v.problems
}

// CheckISISInterface checks one interface's settings.
func CheckISISInterface(ifc ISISInterface, metricStyle string) []string {
	v := &validator{}
	v.isisInterface("isis", ifc, metricStyle, nil)
	return v.problems
}

func (v *validator) isisLevel(p, what, l string, levels ...string) {
	for _, x := range levels {
		if l == x {
			return
		}
	}
	v.addf("%s: %s must be %s", p, what, strings.Join(levels, ", "))
}

func (v *validator) isisInterface(p string, ifc ISISInterface, style string, ifaces map[string]*Interface) {
	p = fmt.Sprintf("%s: interface %s", p, ifc.Name)
	switch {
	case !ifnameRe.MatchString(ifc.Name):
		v.addf("%s: invalid interface name", p)
	case ifaces != nil && ifaces[ifc.Name] == nil:
		v.addf("%s: unknown interface", p)
	case ifaces != nil && ISISLayer3(ifaces[ifc.Name].Kind) && !ifc.Passive:
		v.addf("%s: a %s interface carries no IS-IS (it is not IP); only passive, to announce its networks", p, ifaces[ifc.Name].Kind)
	}
	if !ifc.IPv4 && !ifc.IPv6 {
		v.addf("%s: IPv4, IPv6 or both", p)
	}
	if ifc.CircuitType != "" {
		v.isisLevel(p, "circuit type", ifc.CircuitType, ISISLevel1, ISISLevel12, ISISLevel2)
	}
	if max := ISISMaxMetric(style); ifc.Metric < 0 || ifc.Metric > max {
		v.addf("%s: metric out of range (1-%d)", p, max)
	}
	if ifc.HelloInterval < 0 || ifc.HelloInterval > 600 {
		v.addf("%s: hello interval out of range (1-600)", p)
	}
	if ifc.HelloMultiplier != 0 && (ifc.HelloMultiplier < 2 || ifc.HelloMultiplier > 100) {
		v.addf("%s: hello multiplier out of range (2-100)", p)
	}
	if ifc.Priority != nil && (*ifc.Priority < 0 || *ifc.Priority > 127) {
		v.addf("%s: priority out of range (0-127)", p)
	}
}

// isis checks an IS-IS configuration. refs and ifaces, when not nil, check
// its references.
func (v *validator) isis(p string, s *ISIS, refs *policyRefs, ifaces map[string]*Interface) {
	if n, ok := ParseISISNet(s.NET); !ok || n != s.NET {
		v.addf("%s: NET %q must be an area, a system id and 00, in lower case (49.0001.1921.6800.1001.00)", p, s.NET)
	}
	if s.Level != "" {
		v.isisLevel(p, "level", s.Level, ISISLevel1, ISISLevel12, ISISLevel2)
	}
	switch s.MetricStyle {
	case "", ISISMetricWide, ISISMetricNarrow, ISISMetricTransition:
	default:
		v.addf("%s: metric style must be wide, narrow or transition", p)
	}
	if s.MetricStyle == ISISMetricNarrow && s.IPv6Topology {
		v.addf("%s: the IPv6 topology needs wide metrics", p)
	}
	max := ISISMaxMetric(s.MetricStyle)
	family := func(p, f string) {
		if f != "ipv4" && f != "ipv6" {
			v.addf("%s: family must be ipv4 or ipv6", p)
		}
	}
	defaults := map[string]bool{}
	for _, d := range s.DefaultOriginate {
		dp := fmt.Sprintf("%s: default originate %s %s", p, d.Family, d.Level)
		family(dp, d.Family)
		v.isisLevel(dp, "level", d.Level, "level-1", "level-2")
		if defaults[d.Family+" "+d.Level] {
			v.addf("%s: listed twice", dp)
		}
		defaults[d.Family+" "+d.Level] = true
		if d.Metric < 0 || d.Metric > max {
			v.addf("%s: metric out of range (0-%d)", dp, max)
		}
		if d.RouteMap != "" && !ValidPolicyName(d.RouteMap) {
			v.addf("%s: invalid route map name %q", dp, d.RouteMap)
		}
		refs.routeMap(v, dp, "route map", d.RouteMap)
	}
	redist := map[string]bool{}
	for _, r := range s.Redistribute {
		rp := fmt.Sprintf("%s: redistribute %s %s %s", p, r.Family, r.Source, r.Level)
		family(rp, r.Family)
		switch r.Source {
		case RedistConnected, RedistStatic, RedistBGP, RedistOSPF:
		default:
			v.addf("%s: source must be connected, static, bgp or ospf", rp)
		}
		v.isisLevel(rp, "level", r.Level, "level-1", "level-2")
		k := r.Family + " " + r.Source + " " + r.Level
		if redist[k] {
			v.addf("%s: listed twice", rp)
		}
		redist[k] = true
		if r.Metric < 0 || r.Metric > max {
			v.addf("%s: metric out of range (0-%d)", rp, max)
		}
		if r.RouteMap != "" && !ValidPolicyName(r.RouteMap) {
			v.addf("%s: invalid route map name %q", rp, r.RouteMap)
		}
		refs.routeMap(v, rp, "route map", r.RouteMap)
	}
	names := map[string]bool{}
	for _, ifc := range s.Interfaces {
		v.isisInterface(p, ifc, s.MetricStyle, ifaces)
		if names[ifc.Name] {
			v.addf("%s: interface %s listed twice", p, ifc.Name)
		}
		names[ifc.Name] = true
	}
}

// ISISRunning reports whether the instance runs IS-IS.
func (in *Instance) ISISRunning() bool { return in.ISIS != nil && in.ISIS.Enabled }
