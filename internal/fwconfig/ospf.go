// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

// OSPF runs FRR's ospfd (OSPFv2, IPv4) or ospf6d (OSPFv3, IPv6), with
// zebra, in the instance. Instance.OSPF and Instance.OSPF6 are the two;
// what only OSPFv2 has (network statements, MD5 authentication) is empty
// in OSPFv3's.
type OSPF struct {
	// Enabled runs the daemon; off, it is not started (the default).
	Enabled  bool   `json:"enabled"`
	RouterID string `json:"router_id,omitempty"` // IPv4 address; empty: FRR picks one
	// ReferenceBandwidth (Mbit/s) is the bandwidth of cost 1, from which
	// an interface's cost follows; 0 keeps FRR's (100).
	ReferenceBandwidth  int  `json:"reference_bandwidth,omitempty"`
	LogAdjacencyChanges bool `json:"log_adjacency_changes,omitempty"`
	// MaximumPaths is the number of equal-cost paths installed (0: FRR's).
	MaximumPaths int `json:"maximum_paths,omitempty"`
	// DefaultOriginate announces a default route, while the routing
	// table has one, or Always.
	DefaultOriginate bool `json:"default_originate,omitempty"`
	DefaultAlways    bool `json:"default_always,omitempty"`
	// Areas holds the areas' types; an area named only by an interface or
	// network is a normal one.
	Areas []OSPFArea `json:"areas,omitempty"`
	// Ranges summarise an area's networks into the other areas.
	Ranges []OSPFRange `json:"ranges,omitempty"`
	// Summaries summarise redistributed (external) routes.
	Summaries []OSPFSummary `json:"summaries,omitempty"`
	// Networks (OSPFv2 only) run OSPF on the interfaces with an address
	// in the prefix: the other way to enable it than an interface's area,
	// which FRR does not allow alongside.
	Networks   []OSPFNetwork   `json:"networks,omitempty"`
	Interfaces []OSPFInterface `json:"interfaces,omitempty"`
	// Redistribute announces connected networks, the static routes (the
	// kernel routes the agent installs) or BGP's routes as external.
	Redistribute []OSPFRedistribute `json:"redistribute,omitempty"`
}

// Area types.
const (
	AreaNormal = "normal"
	AreaStub   = "stub"
	AreaNSSA   = "nssa"
)

// OSPFArea is an area's type. NoSummary keeps the other areas' routes
// out of a stub or NSSA area (totally stubby), leaving a default route.
type OSPFArea struct {
	ID        string `json:"id"` // dotted, ParseOSPFArea
	Type      string `json:"type"`
	NoSummary bool   `json:"no_summary,omitempty"`
}

// OSPFRange is an area range: the area's networks inside Prefix are
// announced to the other areas as Prefix, with Cost (0: the highest
// inside), or not at all (NotAdvertise).
type OSPFRange struct {
	Area         string `json:"area"`
	Prefix       string `json:"prefix"`
	NotAdvertise bool   `json:"not_advertise,omitempty"`
	Cost         int    `json:"cost,omitempty"`
}

// OSPFSummary is a summary address of external routes: the redistributed
// routes inside Prefix are announced as Prefix, or not at all.
type OSPFSummary struct {
	Prefix       string `json:"prefix"`
	NotAdvertise bool   `json:"not_advertise,omitempty"`
}

// OSPFNetwork is an OSPFv2 network statement.
type OSPFNetwork struct {
	Prefix string `json:"prefix"`
	Area   string `json:"area"`
}

// Interface network types.
const (
	OSPFBroadcast    = "broadcast"
	OSPFPointToPoint = "point-to-point"
)

// OSPFInterface is OSPF on an interface of the instance (by name): in
// Area, which runs OSPF on all its networks of the IP version, or with
// no area its settings for a network statement's interface (OSPFv2).
type OSPFInterface struct {
	Name string `json:"name"`
	Area string `json:"area,omitempty"`
	// Passive announces the interface's networks but sends no hellos on
	// it: no neighbours there.
	Passive bool `json:"passive,omitempty"`
	// Cost 0 follows from the reference bandwidth; intervals 0 keep FRR's
	// (10 and 40 s).
	Cost          int `json:"cost,omitempty"`
	HelloInterval int `json:"hello_interval,omitempty"`
	DeadInterval  int `json:"dead_interval,omitempty"`
	// Priority in the DR election (0: never DR); nil keeps FRR's (1).
	Priority    *int   `json:"priority,omitempty"`
	NetworkType string `json:"network_type,omitempty"` // "" (the interface's), OSPFBroadcast, OSPFPointToPoint
	// AuthKey (OSPFv2) authenticates with MD5 key AuthKeyID.
	AuthKeyID int    `json:"auth_key_id,omitempty"`
	AuthKey   string `json:"auth_key,omitempty"`
	// BFD watches the neighbours on the interface with BFD, when the
	// interface has it.
	BFD bool `json:"bfd,omitempty"`
}

// OSPF redistribute sources (RedistConnected, RedistStatic, RedistBGP).
const RedistBGP = "bgp"

// OSPFRedistribute redistributes a source as external routes, of
// MetricType 1 or 2 (0: FRR's, 2) with Metric (0: FRR's, 20).
type OSPFRedistribute struct {
	Source     string `json:"source"`
	RouteMap   string `json:"route_map,omitempty"`
	Metric     int    `json:"metric,omitempty"`
	MetricType int    `json:"metric_type,omitempty"`
}

// OSPFRedistSources are what OSPF redistributes.
var OSPFRedistSources = []string{RedistConnected, RedistStatic, RedistBGP}

// ospfAuthKeyRe: printable, no spaces; MD5 keys are up to 16 characters.
var ospfAuthKeyRe = regexp.MustCompile(`^[!-~]{1,16}$`)

// ParseOSPFArea reads an area id, dotted (0.0.0.1) or a number (1), and
// returns it dotted.
func ParseOSPFArea(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return a.String(), true
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return "", false
	}
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}).String(), true
}

// ValidOSPFIntervals reports whether hello and dead intervals (seconds, 0
// for FRR's) are a valid pair.
func ValidOSPFIntervals(hello, dead int) bool {
	if hello < 0 || hello > 65535 || dead < 0 || dead > 65535 {
		return false
	}
	return hello == 0 || dead == 0 || dead > hello
}

// CheckOSPF checks an OSPF configuration (version 2 or 3) on its own:
// without its references to interfaces and route maps.
func CheckOSPF(o *OSPF, version int) []string {
	v := &validator{}
	v.ospf("ospf", o, version, nil, nil)
	return v.problems
}

// CheckOSPFInterface checks one interface's settings.
func CheckOSPFInterface(ifc OSPFInterface, version int) []string {
	v := &validator{}
	v.ospfInterface("ospf", ifc, version, nil)
	return v.problems
}

func (v *validator) ospfArea(p, id string) {
	if a, ok := ParseOSPFArea(id); !ok || a != id {
		v.addf("%s: area %q must be dotted (0.0.0.0)", p, id)
	}
}

func (v *validator) ospfPrefix(p, what, s string, version int) (netip.Prefix, bool) {
	pfx, err := netip.ParsePrefix(s)
	switch {
	case err != nil || pfx != pfx.Masked():
		v.addf("%s: %s %q is not a network prefix", p, what, s)
	case pfx.Addr().Is4() != (version == 2):
		v.addf("%s: %s %s is not an %s prefix", p, what, s, map[int]string{2: "IPv4", 3: "IPv6"}[version])
	default:
		return pfx, true
	}
	return pfx, false
}

func (v *validator) ospfInterface(p string, ifc OSPFInterface, version int, ifaces map[string]*Interface) {
	p = fmt.Sprintf("%s: interface %s", p, ifc.Name)
	switch {
	case !ifnameRe.MatchString(ifc.Name):
		v.addf("%s: invalid interface name", p)
	case ifaces != nil && ifaces[ifc.Name] == nil:
		v.addf("%s: unknown interface", p)
	}
	if ifc.Area != "" {
		v.ospfArea(p, ifc.Area)
	} else if version == 3 {
		v.addf("%s: an area is required", p)
	}
	if ifc.Cost < 0 || ifc.Cost > 65535 {
		v.addf("%s: cost out of range (1-65535)", p)
	}
	if !ValidOSPFIntervals(ifc.HelloInterval, ifc.DeadInterval) {
		v.addf("%s: hello interval 1-65535, dead interval 1-65535 and longer than the hello interval", p)
	}
	if ifc.Priority != nil && (*ifc.Priority < 0 || *ifc.Priority > 255) {
		v.addf("%s: priority out of range (0-255)", p)
	}
	switch ifc.NetworkType {
	case "", OSPFBroadcast, OSPFPointToPoint:
	default:
		v.addf("%s: network type must be broadcast or point-to-point", p)
	}
	switch {
	case ifc.AuthKey == "":
		if ifc.AuthKeyID != 0 {
			v.addf("%s: an authentication key id without a key", p)
		}
	case version != 2:
		v.addf("%s: MD5 authentication is for OSPFv2", p)
	case !ospfAuthKeyRe.MatchString(ifc.AuthKey):
		v.addf("%s: authentication key: 1-16 printable characters, no spaces", p)
	case ifc.AuthKeyID < 1 || ifc.AuthKeyID > 255:
		v.addf("%s: authentication key id out of range (1-255)", p)
	}
}

// ospf checks an OSPF configuration. refs and ifaces, when not nil, check
// its references.
func (v *validator) ospf(p string, o *OSPF, version int, refs *policyRefs, ifaces map[string]*Interface) {
	if o.RouterID != "" {
		if a, err := netip.ParseAddr(o.RouterID); err != nil || !a.Is4() {
			v.addf("%s: router id must be an IPv4 address", p)
		}
	}
	if o.ReferenceBandwidth < 0 || o.ReferenceBandwidth > 4294967 {
		v.addf("%s: reference bandwidth out of range (1-4294967 Mbit/s)", p)
	}
	if o.MaximumPaths < 0 || o.MaximumPaths > 64 {
		v.addf("%s: maximum paths out of range (1-64)", p)
	}
	if o.DefaultAlways && !o.DefaultOriginate {
		v.addf("%s: default route always: only with default originate", p)
	}
	areas := map[string]bool{}
	for _, a := range o.Areas {
		ap := fmt.Sprintf("%s: area %s", p, a.ID)
		v.ospfArea(p, a.ID)
		if areas[a.ID] {
			v.addf("%s: listed twice", ap)
		}
		areas[a.ID] = true
		switch a.Type {
		case AreaNormal:
			if a.NoSummary {
				v.addf("%s: no summary is for a stub or NSSA area", ap)
			}
		case AreaStub, AreaNSSA:
			if a.ID == "0.0.0.0" {
				v.addf("%s: the backbone can't be a stub or NSSA area", ap)
			}
		default:
			v.addf("%s: type must be normal, stub or nssa", ap)
		}
	}
	ranges := map[string]bool{}
	for _, r := range o.Ranges {
		v.ospfArea(p+": range "+r.Prefix, r.Area)
		if _, ok := v.ospfPrefix(p, "range", r.Prefix, version); ok {
			if ranges[r.Area+" "+r.Prefix] {
				v.addf("%s: range %s in area %s listed twice", p, r.Prefix, r.Area)
			}
			ranges[r.Area+" "+r.Prefix] = true
		}
		if r.Cost < 0 || r.Cost > 16777215 {
			v.addf("%s: range %s: cost out of range (0-16777215)", p, r.Prefix)
		}
		if r.NotAdvertise && r.Cost != 0 {
			v.addf("%s: range %s: a range not advertised has no cost", p, r.Prefix)
		}
	}
	summaries := map[string]bool{}
	for _, s := range o.Summaries {
		if _, ok := v.ospfPrefix(p, "summary address", s.Prefix, version); ok {
			if summaries[s.Prefix] {
				v.addf("%s: summary address %s listed twice", p, s.Prefix)
			}
			summaries[s.Prefix] = true
		}
	}
	if version != 2 && len(o.Networks) > 0 {
		v.addf("%s: network statements are for OSPFv2; OSPFv3 runs on interfaces", p)
	}
	networks := map[string]bool{}
	for _, n := range o.Networks {
		v.ospfArea(p+": network "+n.Prefix, n.Area)
		if _, ok := v.ospfPrefix(p, "network", n.Prefix, 2); ok {
			if networks[n.Prefix] {
				v.addf("%s: network %s listed twice", p, n.Prefix)
			}
			networks[n.Prefix] = true
		}
	}
	names := map[string]bool{}
	for _, ifc := range o.Interfaces {
		v.ospfInterface(p, ifc, version, ifaces)
		if names[ifc.Name] {
			v.addf("%s: interface %s listed twice", p, ifc.Name)
		}
		names[ifc.Name] = true
		if ifc.Area != "" && len(o.Networks) > 0 {
			v.addf("%s: interface %s: an interface area and network statements can't be used together; leave the area empty to set the interface's options only", p, ifc.Name)
		}
	}
	redist := map[string]bool{}
	for _, r := range o.Redistribute {
		rp := fmt.Sprintf("%s: redistribute %s", p, r.Source)
		switch r.Source {
		case RedistConnected, RedistStatic, RedistBGP:
		default:
			v.addf("%s: source must be connected, static or bgp", rp)
		}
		if redist[r.Source] {
			v.addf("%s: listed twice", rp)
		}
		redist[r.Source] = true
		if r.Metric < 0 || r.Metric > 16777214 {
			v.addf("%s: metric out of range (0-16777214)", rp)
		}
		if r.MetricType != 0 && r.MetricType != 1 && r.MetricType != 2 {
			v.addf("%s: metric type must be 1 or 2", rp)
		}
		if r.RouteMap != "" && !ValidPolicyName(r.RouteMap) {
			v.addf("%s: invalid route map name %q", rp, r.RouteMap)
		}
		refs.routeMap(v, rp, "route map", r.RouteMap)
	}
}

// OSPFRunning reports whether the instance runs OSPFv2 (version 2) or
// OSPFv3 (3).
func (in *Instance) OSPFRunning(version int) bool {
	o := in.OSPF
	if version == 3 {
		o = in.OSPF6
	}
	return o != nil && o.Enabled
}

// FRRRunning reports whether the instance runs FRR: for BGP, OSPF, VRRP
// or BFD.
func (in *Instance) FRRRunning() bool {
	return in.BGPRunning() || in.OSPFRunning(2) || in.OSPFRunning(3) || in.VRRPRunning() || in.BFDRunning()
}
