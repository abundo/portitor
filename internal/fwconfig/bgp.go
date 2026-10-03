// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"cmp"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// BGP runs FRR's bgpd (with zebra) in the instance. The routing policy
// objects it refers to by name (prefix lists, AS path lists, community
// lists, route maps) are the instance's RoutingPolicy.
type BGP struct {
	// Enabled runs FRR; off, its unit is stopped (the default).
	Enabled  bool   `json:"enabled"`
	ASN      uint32 `json:"asn"`
	RouterID string `json:"router_id,omitempty"` // IPv4 address; empty: FRR picks one
	// Keepalive and Hold are the default timers in seconds; 0 keeps
	// FRR's (60, 180).
	Keepalive int `json:"keepalive,omitempty"`
	Hold      int `json:"hold,omitempty"`
	// EBGPRequiresPolicy is FRR's RFC 8212 default: an eBGP neighbour
	// without a route map in and out exchanges no routes.
	EBGPRequiresPolicy bool `json:"ebgp_requires_policy,omitempty"`
	LogNeighborChanges bool `json:"log_neighbor_changes,omitempty"`
	GracefulRestart    bool `json:"graceful_restart,omitempty"`
	// MultipathRelax lets paths of different neighbouring ASes share
	// load (bgp bestpath as-path multipath-relax); MaximumPaths is the
	// number of eBGP paths installed (0: FRR's default).
	MultipathRelax bool `json:"multipath_relax,omitempty"`
	MaximumPaths   int  `json:"maximum_paths,omitempty"`
	// Networks are announced when the routing table has them.
	Networks   []BGPNetwork   `json:"networks,omitempty"`
	Aggregates []BGPAggregate `json:"aggregates,omitempty"`
	// Redistribute announces connected networks or the static routes
	// (the kernel routes the agent installs).
	Redistribute []BGPRedistribute `json:"redistribute,omitempty"`
	PeerGroups   []BGPPeer         `json:"peer_groups,omitempty"`
	Neighbors    []BGPPeer         `json:"neighbors,omitempty"`
}

// BGPNetwork is a network statement, of its prefix's IP version.
type BGPNetwork struct {
	Prefix   string `json:"prefix"`
	RouteMap string `json:"route_map,omitempty"`
}

// BGPAggregate is an aggregate-address of its prefix's IP version.
type BGPAggregate struct {
	Prefix      string `json:"prefix"`
	SummaryOnly bool   `json:"summary_only,omitempty"`
	ASSet       bool   `json:"as_set,omitempty"`
}

// Redistribute sources.
const (
	RedistConnected = "connected"
	RedistStatic    = "static"
)

// BGPRedistribute redistributes a source into an address family.
type BGPRedistribute struct {
	Family   string `json:"family"` // ipv4, ipv6
	Source   string `json:"source"` // RedistConnected, RedistStatic
	RouteMap string `json:"route_map,omitempty"`
}

// BGPPeer is a neighbour (Address set) or a peer group (Name set). A
// neighbour in a PeerGroup takes the group's settings; its own add to them.
type BGPPeer struct {
	Name      string `json:"name,omitempty"`
	Address   string `json:"address,omitempty"`
	PeerGroup string `json:"peer_group,omitempty"`
	// RemoteAS is an AS number, "internal" or "external"; a neighbour in
	// a group that has one may leave it empty.
	RemoteAS    string `json:"remote_as,omitempty"`
	Description string `json:"description,omitempty"`
	Password    string `json:"password,omitempty"` // TCP MD5
	// EBGPMultihop is the TTL of an eBGP session to a neighbour that is
	// not directly connected; 0 is off.
	EBGPMultihop int `json:"ebgp_multihop,omitempty"`
	// UpdateSource is an interface of the instance or an address.
	UpdateSource string `json:"update_source,omitempty"`
	Shutdown     bool   `json:"shutdown,omitempty"`
	Keepalive    int    `json:"keepalive,omitempty"`
	Hold         int    `json:"hold,omitempty"`
	// Passive waits for the neighbour to connect.
	Passive bool             `json:"passive,omitempty"`
	IPv4    BGPAddressFamily `json:"ipv4"`
	IPv6    BGPAddressFamily `json:"ipv6"`
}

// BGPAddressFamily is a peer's settings in one address family (unicast).
// In and out, a prefix list or a route map filters, not both.
type BGPAddressFamily struct {
	Activate             bool   `json:"activate,omitempty"`
	PrefixListIn         string `json:"prefix_list_in,omitempty"`
	PrefixListOut        string `json:"prefix_list_out,omitempty"`
	RouteMapIn           string `json:"route_map_in,omitempty"`
	RouteMapOut          string `json:"route_map_out,omitempty"`
	NextHopSelf          bool   `json:"next_hop_self,omitempty"`
	RemovePrivateAS      bool   `json:"remove_private_as,omitempty"`
	SoftReconfiguration  bool   `json:"soft_reconfiguration,omitempty"`
	DefaultOriginate     bool   `json:"default_originate,omitempty"`
	RouteReflectorClient bool   `json:"route_reflector_client,omitempty"`
	// AllowASIn accepts routes with the local AS in their path this many
	// times (0: off); MaximumPrefix tears the session down above this
	// many prefixes (0: no limit).
	AllowASIn     int `json:"allowas_in,omitempty"`
	MaximumPrefix int `json:"maximum_prefix,omitempty"`
}

// RoutingPolicy holds an instance's routing policy objects.
type RoutingPolicy struct {
	PrefixLists    []PrefixList    `json:"prefix_lists,omitempty"`
	ASPathLists    []ASPathList    `json:"as_path_lists,omitempty"`
	CommunityLists []CommunityList `json:"community_lists,omitempty"`
	RouteMaps      []RouteMap      `json:"route_maps,omitempty"`
}

// Empty reports whether the policy has no objects.
func (p *RoutingPolicy) Empty() bool {
	return len(p.PrefixLists) == 0 && len(p.ASPathLists) == 0 && len(p.CommunityLists) == 0 && len(p.RouteMaps) == 0
}

// Policy actions.
const (
	Permit = "permit"
	Deny   = "deny"
)

// PrefixList is an ip or ipv6 prefix-list.
type PrefixList struct {
	Name        string            `json:"name"`
	Family      string            `json:"family"` // ipv4, ipv6
	Description string            `json:"description,omitempty"`
	Entries     []PrefixListEntry `json:"entries"`
}

// PrefixListEntry matches Prefix, or with GE/LE the prefixes inside it of
// those lengths (0: not set).
type PrefixListEntry struct {
	Seq    int    `json:"seq"`
	Action string `json:"action"`
	Prefix string `json:"prefix"` // a CIDR, or "any"
	GE     int    `json:"ge,omitempty"`
	LE     int    `json:"le,omitempty"`
}

// ASPathList is a bgp as-path access-list.
type ASPathList struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Entries     []ASPathEntry `json:"entries"`
}

type ASPathEntry struct {
	Action string `json:"action"`
	Regex  string `json:"regex"`
}

// Community list kinds.
const (
	CommunityStandard      = "standard"
	CommunityExpanded      = "expanded"
	CommunityLargeStandard = "large-standard"
	CommunityLargeExpanded = "large-expanded"
)

// CommunityList is a bgp community-list or large-community-list.
type CommunityList struct {
	Name        string           `json:"name"`
	Kind        string           `json:"kind"`
	Description string           `json:"description,omitempty"`
	Entries     []CommunityEntry `json:"entries"`
}

// Large reports whether the list holds large communities.
func (c *CommunityList) Large() bool {
	return c.Kind == CommunityLargeStandard || c.Kind == CommunityLargeExpanded
}

// CommunityEntry's Value is communities separated by spaces (standard
// kinds) or a regular expression (expanded kinds).
type CommunityEntry struct {
	Action string `json:"action"`
	Value  string `json:"value"`
}

// RouteMap is a route-map: its entries are tried in Seq order.
type RouteMap struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Entries     []RouteMapEntry `json:"entries"`
}

// Route origins (set origin).
var Origins = []string{"igp", "egp", "incomplete"}

// RouteMapEntry matches on all its match fields (empty: any) and, if it
// permits, sets its set fields. Pointers are unset when nil.
type RouteMapEntry struct {
	Seq         int    `json:"seq"`
	Action      string `json:"action"`
	Description string `json:"description,omitempty"`
	// MatchPrefixList is a prefix list of either IP version (match ip or
	// ipv6 address prefix-list); MatchNextHop one for the next hop.
	MatchPrefixList string `json:"match_prefix_list,omitempty"`
	MatchNextHop    string `json:"match_next_hop,omitempty"`
	MatchASPath     string `json:"match_as_path,omitempty"`
	MatchCommunity  string `json:"match_community,omitempty"` // a community list, large or not
	MatchMetric     *int64 `json:"match_metric,omitempty"`
	MatchTag        *int64 `json:"match_tag,omitempty"`

	SetLocalPreference *int64 `json:"set_local_preference,omitempty"`
	SetMetric          *int64 `json:"set_metric,omitempty"`
	SetWeight          *int64 `json:"set_weight,omitempty"`
	// SetASPathPrepend is AS numbers separated by spaces.
	SetASPathPrepend string `json:"set_as_path_prepend,omitempty"`
	// SetCommunity is communities separated by spaces, or "none";
	// SetCommunityAdditive adds them to the route's.
	SetCommunity         string `json:"set_community,omitempty"`
	SetCommunityAdditive bool   `json:"set_community_additive,omitempty"`
	SetLargeCommunity    string `json:"set_large_community,omitempty"`
	SetNextHop           string `json:"set_next_hop,omitempty"` // an address of either version
	SetOrigin            string `json:"set_origin,omitempty"`
	// OnMatchNext goes on to the next entry after a permit instead of
	// leaving the route map.
	OnMatchNext bool `json:"on_match_next,omitempty"`
}

var (
	// policyNameRe is a routing policy object or peer group name (FRR's
	// WORD; no spaces, no "!").
	policyNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	// bgpRegexRe are the characters of an AS path or expanded community
	// regular expression: the rest of FRR's line is the expression.
	bgpRegexRe       = regexp.MustCompile(`^[A-Za-z0-9_^$.*+?()\[\]{}|\\:, -]{1,200}$`)
	communityRe      = regexp.MustCompile(`^[0-9]{1,5}:[0-9]{1,5}$`)
	largeCommunityRe = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}:[0-9]{1,10}$`)
	// bgpPasswordRe: printable, no spaces (FRR takes one word).
	bgpPasswordRe = regexp.MustCompile(`^[!-~]{1,80}$`)
)

// WellKnownCommunities may stand for a standard community.
var WellKnownCommunities = []string{"internet", "local-AS", "no-advertise", "no-export", "graceful-shutdown", "blackhole", "no-peer", "accept-own", "no-llgr", "llgr-stale"}

func ValidPolicyName(s string) bool { return policyNameRe.MatchString(s) }

// ParseASN reads an AS number (1-4294967295, asplain).
func ParseASN(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil && n > 0
}

// validCommunities checks a list of communities separated by spaces.
func validCommunities(s string, large bool) bool {
	f := strings.Fields(s)
	if len(f) == 0 || len(s) > 400 {
		return false
	}
	for _, c := range f {
		switch {
		case large:
			if !largeCommunityRe.MatchString(c) {
				return false
			}
			for _, part := range strings.Split(c, ":") {
				if _, err := strconv.ParseUint(part, 10, 32); err != nil {
					return false
				}
			}
		case slices.Contains(WellKnownCommunities, c):
		case communityRe.MatchString(c):
			for _, part := range strings.Split(c, ":") {
				if n, _ := strconv.Atoi(part); n > 65535 {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// CheckPrefixList checks a prefix list on its own; nil if it is fine.
func CheckPrefixList(pl PrefixList) []string {
	v := &validator{}
	v.prefixList("prefix list "+pl.Name, pl)
	return v.problems
}

// CheckASPathList checks an AS path list on its own.
func CheckASPathList(l ASPathList) []string {
	v := &validator{}
	v.asPathList("as path list "+l.Name, l)
	return v.problems
}

// CheckCommunityList checks a community list on its own.
func CheckCommunityList(l CommunityList) []string {
	v := &validator{}
	v.communityList("community list "+l.Name, l)
	return v.problems
}

// CheckRouteMap checks a route map on its own, without its references.
func CheckRouteMap(m RouteMap) []string {
	v := &validator{}
	v.routeMap("route map "+m.Name, m, nil)
	return v.problems
}

// CheckBGPPeer checks a neighbour or peer group on its own, without its
// references.
func CheckBGPPeer(peer BGPPeer) []string {
	v := &validator{}
	v.bgpPeer("bgp", peer, nil, nil)
	return v.problems
}

func (v *validator) policyName(p, name string) {
	if !policyNameRe.MatchString(name) {
		v.addf("%s: name must be letters, digits, _ . -, starting with a letter or digit, at most 63 characters", p)
	}
}

func (v *validator) seqs(p string, seqs []int) {
	seen := map[int]bool{}
	for _, s := range seqs {
		if s < 1 || s > 65535 {
			v.addf("%s: sequence number %d out of range (1-65535)", p, s)
		}
		if seen[s] {
			v.addf("%s: sequence number %d used twice", p, s)
		}
		seen[s] = true
	}
}

func (v *validator) policyAction(p, a string) {
	if a != Permit && a != Deny {
		v.addf("%s: action must be permit or deny", p)
	}
}

func (v *validator) prefixList(p string, pl PrefixList) {
	v.policyName(p, pl.Name)
	checkComment(v, p, pl.Description)
	if pl.Family != "ipv4" && pl.Family != "ipv6" {
		v.addf("%s: family must be ipv4 or ipv6", p)
		return
	}
	var seqs []int
	for _, e := range pl.Entries {
		ep := fmt.Sprintf("%s: entry %d", p, e.Seq)
		seqs = append(seqs, e.Seq)
		v.policyAction(ep, e.Action)
		if e.Prefix == "any" {
			if e.GE != 0 || e.LE != 0 {
				v.addf("%s: any takes no ge or le", ep)
			}
			continue
		}
		pfx, err := netip.ParsePrefix(e.Prefix)
		if err != nil || pfx != pfx.Masked() {
			v.addf("%s: %q is not a network prefix (e.g. 10.0.0.0/8)", ep, e.Prefix)
			continue
		}
		if pfx.Addr().Is4() != (pl.Family == "ipv4") {
			v.addf("%s: %s is not an %s prefix", ep, e.Prefix, pl.Family)
			continue
		}
		maxBits := pfx.Addr().BitLen()
		if e.GE != 0 && (e.GE <= pfx.Bits() || e.GE > maxBits) {
			v.addf("%s: ge %d must be longer than /%d and at most %d", ep, e.GE, pfx.Bits(), maxBits)
		}
		if e.LE != 0 && (e.LE <= pfx.Bits() || e.LE > maxBits) {
			v.addf("%s: le %d must be longer than /%d and at most %d", ep, e.LE, pfx.Bits(), maxBits)
		}
		if e.GE != 0 && e.LE != 0 && e.GE > e.LE {
			v.addf("%s: ge %d is more than le %d", ep, e.GE, e.LE)
		}
	}
	v.seqs(p, seqs)
}

func (v *validator) asPathList(p string, l ASPathList) {
	v.policyName(p, l.Name)
	checkComment(v, p, l.Description)
	for i, e := range l.Entries {
		ep := fmt.Sprintf("%s: entry %d", p, i+1)
		v.policyAction(ep, e.Action)
		if !bgpRegexRe.MatchString(e.Regex) {
			v.addf("%s: regular expression %q: use digits, letters, spaces and _ ^ $ . * + ? ( ) [ ] { } | \\ : , -", ep, e.Regex)
		}
	}
}

func (v *validator) communityList(p string, l CommunityList) {
	v.policyName(p, l.Name)
	checkComment(v, p, l.Description)
	switch l.Kind {
	case CommunityStandard, CommunityExpanded, CommunityLargeStandard, CommunityLargeExpanded:
	default:
		v.addf("%s: invalid kind %q", p, l.Kind)
		return
	}
	for i, e := range l.Entries {
		ep := fmt.Sprintf("%s: entry %d", p, i+1)
		v.policyAction(ep, e.Action)
		switch l.Kind {
		case CommunityStandard:
			if !validCommunities(e.Value, false) {
				v.addf("%s: %q: communities are AS:NN (0-65535 each) or well-known names, separated by spaces", ep, e.Value)
			}
		case CommunityLargeStandard:
			if !validCommunities(e.Value, true) {
				v.addf("%s: %q: large communities are A:B:C, separated by spaces", ep, e.Value)
			}
		default:
			if !bgpRegexRe.MatchString(e.Value) {
				v.addf("%s: regular expression %q has characters that are not allowed", ep, e.Value)
			}
		}
	}
}

// policyRefs are the names of an instance's routing policy objects.
type policyRefs struct {
	prefixLists map[string]string // name -> family
	asPaths     map[string]bool
	communities map[string]bool
	routeMaps   map[string]bool
}

func newPolicyRefs(rp *RoutingPolicy) *policyRefs {
	r := &policyRefs{prefixLists: map[string]string{}, asPaths: map[string]bool{}, communities: map[string]bool{}, routeMaps: map[string]bool{}}
	for _, pl := range rp.PrefixLists {
		r.prefixLists[pl.Name] = pl.Family
	}
	for _, l := range rp.ASPathLists {
		r.asPaths[l.Name] = true
	}
	for _, l := range rp.CommunityLists {
		r.communities[l.Name] = true
	}
	for _, m := range rp.RouteMaps {
		r.routeMaps[m.Name] = true
	}
	return r
}

// prefixList checks a reference to a prefix list; family "" takes either.
func (r *policyRefs) prefixList(v *validator, p, what, name, family string) {
	if name == "" || r == nil {
		return
	}
	fam, ok := r.prefixLists[name]
	switch {
	case !ok:
		v.addf("%s: %s: unknown prefix list %q", p, what, name)
	case family != "" && fam != family:
		v.addf("%s: %s: prefix list %s is %s, not %s", p, what, name, fam, family)
	}
}

func (r *policyRefs) routeMap(v *validator, p, what, name string) {
	if name != "" && r != nil && !r.routeMaps[name] {
		v.addf("%s: %s: unknown route map %q", p, what, name)
	}
}

func (v *validator) routeMap(p string, m RouteMap, refs *policyRefs) {
	v.policyName(p, m.Name)
	checkComment(v, p, m.Description)
	var seqs []int
	for _, e := range m.Entries {
		ep := fmt.Sprintf("%s: entry %d", p, e.Seq)
		seqs = append(seqs, e.Seq)
		v.policyAction(ep, e.Action)
		checkComment(v, ep, e.Description)
		for _, ref := range []struct{ what, name string }{
			{"match prefix list", e.MatchPrefixList}, {"match next hop", e.MatchNextHop},
			{"match as path", e.MatchASPath}, {"match community", e.MatchCommunity},
		} {
			if ref.name != "" && !policyNameRe.MatchString(ref.name) {
				v.addf("%s: %s: invalid name %q", ep, ref.what, ref.name)
			}
		}
		if refs != nil {
			refs.prefixList(v, ep, "match prefix list", e.MatchPrefixList, "")
			refs.prefixList(v, ep, "match next hop", e.MatchNextHop, "")
			if e.MatchASPath != "" && !refs.asPaths[e.MatchASPath] {
				v.addf("%s: unknown as path list %q", ep, e.MatchASPath)
			}
			if e.MatchCommunity != "" && !refs.communities[e.MatchCommunity] {
				v.addf("%s: unknown community list %q", ep, e.MatchCommunity)
			}
		}
		for _, n := range []struct {
			what   string
			val    *int64
			lo, hi int64
		}{
			{"match metric", e.MatchMetric, 0, 4294967295}, {"match tag", e.MatchTag, 1, 4294967295},
			{"set local preference", e.SetLocalPreference, 0, 4294967295},
			{"set metric", e.SetMetric, 0, 4294967295}, {"set weight", e.SetWeight, 0, 4294967295},
		} {
			if n.val != nil && (*n.val < n.lo || *n.val > n.hi) {
				v.addf("%s: %s %d out of range (%d-%d)", ep, n.what, *n.val, n.lo, n.hi)
			}
		}
		if e.SetASPathPrepend != "" {
			f := strings.Fields(e.SetASPathPrepend)
			if len(f) > 10 {
				v.addf("%s: set as path prepend: at most 10 AS numbers", ep)
			}
			for _, a := range f {
				if _, ok := ParseASN(a); !ok {
					v.addf("%s: set as path prepend: %q is not an AS number", ep, a)
				}
			}
		}
		if e.SetCommunity != "" && e.SetCommunity != "none" && !validCommunities(e.SetCommunity, false) {
			v.addf("%s: set community %q: AS:NN or well-known names separated by spaces, or none", ep, e.SetCommunity)
		}
		if e.SetCommunityAdditive && (e.SetCommunity == "" || e.SetCommunity == "none") {
			v.addf("%s: set community additive needs communities to add", ep)
		}
		if e.SetLargeCommunity != "" && !validCommunities(e.SetLargeCommunity, true) {
			v.addf("%s: set large community %q: A:B:C separated by spaces", ep, e.SetLargeCommunity)
		}
		if e.SetNextHop != "" {
			if _, err := ParseAddr(e.SetNextHop); err != nil {
				v.addf("%s: set next hop %q is not an address", ep, e.SetNextHop)
			}
		}
		if e.SetOrigin != "" && !slices.Contains(Origins, e.SetOrigin) {
			v.addf("%s: set origin must be igp, egp or incomplete", ep)
		}
	}
	v.seqs(p, seqs)
}

// validRemoteAS reports whether s is an AS number, internal or external.
func validRemoteAS(s string) bool {
	if s == "internal" || s == "external" {
		return true
	}
	_, ok := ParseASN(s)
	return ok
}

// ValidBGPTimers reports whether keepalive and hold (seconds, 0 for
// FRR's) are a valid pair.
func ValidBGPTimers(keepalive, hold int) bool {
	if keepalive == 0 && hold == 0 {
		return true
	}
	return keepalive >= 1 && keepalive <= 65535 && (hold == 0 || hold >= 3 && hold <= 65535 && hold >= keepalive)
}

// bgpPeer checks a neighbour or peer group. refs and ifaces, when not nil,
// check its references.
func (v *validator) bgpPeer(p string, peer BGPPeer, refs *policyRefs, ifaces map[string]*Interface) {
	if peer.Address != "" {
		p = fmt.Sprintf("%s: neighbour %s", p, peer.Address)
		if _, err := ParseAddr(peer.Address); err != nil {
			v.addf("%s: not an IP address", p)
		}
		if peer.PeerGroup != "" && !policyNameRe.MatchString(peer.PeerGroup) {
			v.addf("%s: invalid peer group %q", p, peer.PeerGroup)
		}
	} else {
		p = fmt.Sprintf("%s: peer group %s", p, peer.Name)
		v.policyName(p, peer.Name)
		if peer.PeerGroup != "" {
			v.addf("%s: a peer group can't be in another", p)
		}
	}
	if peer.RemoteAS != "" && !validRemoteAS(peer.RemoteAS) {
		v.addf("%s: remote AS must be an AS number (1-4294967295), internal or external", p)
	}
	checkComment(v, p, peer.Description)
	if peer.Password != "" && !bgpPasswordRe.MatchString(peer.Password) {
		v.addf("%s: password: 1-80 printable characters, no spaces", p)
	}
	if peer.EBGPMultihop < 0 || peer.EBGPMultihop > 255 {
		v.addf("%s: ebgp multihop TTL out of range (1-255)", p)
	}
	if peer.UpdateSource != "" {
		_, err := ParseAddr(peer.UpdateSource)
		switch {
		case err == nil:
		case !ifnameRe.MatchString(peer.UpdateSource):
			v.addf("%s: update source %q is neither an address nor an interface", p, peer.UpdateSource)
		case ifaces != nil && ifaces[peer.UpdateSource] == nil:
			v.addf("%s: update source: unknown interface %q", p, peer.UpdateSource)
		}
	}
	if !ValidBGPTimers(peer.Keepalive, peer.Hold) {
		v.addf("%s: timers: keepalive 1-65535, hold 3-65535 and not less than keepalive", p)
	}
	for _, af := range []struct {
		fam string
		s   BGPAddressFamily
	}{{"ipv4", peer.IPv4}, {"ipv6", peer.IPv6}} {
		ap := p + ": " + af.fam
		if af.s.PrefixListIn != "" && af.s.RouteMapIn != "" {
			v.addf("%s: filter in by a prefix list or a route map, not both", ap)
		}
		if af.s.PrefixListOut != "" && af.s.RouteMapOut != "" {
			v.addf("%s: filter out by a prefix list or a route map, not both", ap)
		}
		for _, n := range []string{af.s.PrefixListIn, af.s.PrefixListOut, af.s.RouteMapIn, af.s.RouteMapOut} {
			if n != "" && !policyNameRe.MatchString(n) {
				v.addf("%s: invalid filter name %q", ap, n)
			}
		}
		refs.prefixList(v, ap, "prefix list in", af.s.PrefixListIn, af.fam)
		refs.prefixList(v, ap, "prefix list out", af.s.PrefixListOut, af.fam)
		refs.routeMap(v, ap, "route map in", af.s.RouteMapIn)
		refs.routeMap(v, ap, "route map out", af.s.RouteMapOut)
		if af.s.AllowASIn < 0 || af.s.AllowASIn > 10 {
			v.addf("%s: allowas-in out of range (1-10)", ap)
		}
		if af.s.MaximumPrefix < 0 || af.s.MaximumPrefix > 4294967295 {
			v.addf("%s: maximum prefix out of range", ap)
		}
	}
}

// routing checks an instance's routing policy and BGP.
func (v *validator) routing(p string, in *Instance, ifaces map[string]*Interface) {
	rp := &in.RoutingPolicy
	seen := map[string]bool{}
	dup := func(kind, name string) {
		if seen[kind+"\x00"+name] {
			v.addf("%s: %s %s: duplicate name", p, kind, name)
		}
		seen[kind+"\x00"+name] = true
	}
	for _, pl := range rp.PrefixLists {
		// ip and ipv6 prefix lists are separate in FRR, but one name for
		// both would make a reference ambiguous.
		dup("prefix list", pl.Name)
		v.prefixList(fmt.Sprintf("%s: prefix list %s", p, pl.Name), pl)
	}
	for _, l := range rp.ASPathLists {
		dup("as path list", l.Name)
		v.asPathList(fmt.Sprintf("%s: as path list %s", p, l.Name), l)
	}
	communityNames := map[string]bool{}
	for _, l := range rp.CommunityLists {
		dup("community list", l.Name)
		communityNames[l.Name] = true
		v.communityList(fmt.Sprintf("%s: community list %s", p, l.Name), l)
	}
	refs := newPolicyRefs(rp)
	for _, m := range rp.RouteMaps {
		dup("route map", m.Name)
		v.routeMap(fmt.Sprintf("%s: route map %s", p, m.Name), m, refs)
	}

	b := in.BGP
	if b == nil {
		return
	}
	bp := p + ": bgp"
	if b.ASN == 0 {
		v.addf("%s: local AS is required", bp)
	}
	if b.RouterID != "" {
		if a, err := netip.ParseAddr(b.RouterID); err != nil || !a.Is4() {
			v.addf("%s: router id must be an IPv4 address", bp)
		}
	}
	if !ValidBGPTimers(b.Keepalive, b.Hold) {
		v.addf("%s: timers: keepalive 1-65535, hold 3-65535 and not less than keepalive", bp)
	}
	if b.MaximumPaths < 0 || b.MaximumPaths > 128 {
		v.addf("%s: maximum paths out of range (1-128)", bp)
	}
	networks := map[netip.Prefix]bool{}
	for _, n := range b.Networks {
		pfx, err := netip.ParsePrefix(n.Prefix)
		if err != nil || pfx != pfx.Masked() {
			v.addf("%s: network %q is not a network prefix", bp, n.Prefix)
			continue
		}
		if networks[pfx] {
			v.addf("%s: network %s listed twice", bp, pfx)
		}
		networks[pfx] = true
		refs.routeMap(v, bp, "network "+n.Prefix, n.RouteMap)
	}
	aggregates := map[netip.Prefix]bool{}
	for _, a := range b.Aggregates {
		pfx, err := netip.ParsePrefix(a.Prefix)
		if err != nil || pfx != pfx.Masked() {
			v.addf("%s: aggregate address %q is not a network prefix", bp, a.Prefix)
			continue
		}
		if aggregates[pfx] {
			v.addf("%s: aggregate address %s listed twice", bp, pfx)
		}
		aggregates[pfx] = true
	}
	redist := map[string]bool{}
	for _, r := range b.Redistribute {
		rp := fmt.Sprintf("%s: redistribute %s %s", bp, r.Family, r.Source)
		if r.Family != "ipv4" && r.Family != "ipv6" {
			v.addf("%s: family must be ipv4 or ipv6", rp)
		}
		if r.Source != RedistConnected && r.Source != RedistStatic {
			v.addf("%s: source must be connected or static", rp)
		}
		if redist[r.Family+r.Source] {
			v.addf("%s: listed twice", rp)
		}
		redist[r.Family+r.Source] = true
		refs.routeMap(v, rp, "route map", r.RouteMap)
	}
	groups := map[string]bool{}
	for _, g := range b.PeerGroups {
		if g.Address != "" {
			v.addf("%s: peer group %s has an address", bp, g.Name)
		}
		if groups[g.Name] {
			v.addf("%s: peer group %s: duplicate name", bp, g.Name)
		}
		groups[g.Name] = true
		v.bgpPeer(bp, g, refs, ifaces)
	}
	addrs := map[netip.Addr]bool{}
	for _, n := range b.Neighbors {
		if n.Address == "" {
			v.addf("%s: a neighbour needs an address", bp)
			continue
		}
		v.bgpPeer(bp, n, refs, ifaces)
		a, err := ParseAddr(n.Address)
		if err != nil {
			continue
		}
		if addrs[a] {
			v.addf("%s: neighbour %s: listed twice", bp, n.Address)
		}
		addrs[a] = true
		if n.PeerGroup != "" && !groups[n.PeerGroup] {
			v.addf("%s: neighbour %s: unknown peer group %q", bp, n.Address, n.PeerGroup)
		}
		if n.RemoteAS == "" && (n.PeerGroup == "" || b.peerGroup(n.PeerGroup).RemoteAS == "") {
			v.addf("%s: neighbour %s: remote AS is required (on the neighbour or its peer group)", bp, n.Address)
		}
		group := b.peerGroup(n.PeerGroup)
		remote := cmp.Or(n.RemoteAS, group.RemoteAS)
		for _, af := range []struct {
			fam      string
			own, grp BGPAddressFamily
		}{{"ipv4", n.IPv4, group.IPv4}, {"ipv6", n.IPv6, group.IPv6}} {
			if (af.own.RouteReflectorClient || af.grp.RouteReflectorClient) && !b.internal(remote) {
				v.addf("%s: neighbour %s: %s: a route reflector client must be an iBGP neighbour (remote AS internal or %d)", bp, n.Address, af.fam, b.ASN)
			}
		}
		b.externalOnly(v, fmt.Sprintf("%s: neighbour %s", bp, n.Address), n, remote)
	}
	for _, g := range b.PeerGroups {
		b.externalOnly(v, fmt.Sprintf("%s: peer group %s", bp, g.Name), g, g.RemoteAS)
	}
}

// CheckBGPSession checks a peer against the local AS (asn; 0 when not set
// yet): what is for eBGP or iBGP peers only. remote is its remote AS, its
// peer group's when it has none.
func CheckBGPSession(asn uint32, peer BGPPeer, remote string) []string {
	v := &validator{}
	b := &BGP{ASN: asn}
	if asn != 0 || remote == "internal" {
		b.externalOnly(v, "bgp", peer, remote)
		if (peer.IPv4.RouteReflectorClient || peer.IPv6.RouteReflectorClient) && remote != "" && !b.internal(remote) {
			v.addf("a route reflector client must be an iBGP neighbour (remote AS internal or the local AS)")
		}
	}
	return v.problems
}

// externalOnly refuses on an iBGP peer what FRR allows on eBGP only.
func (b *BGP) externalOnly(v *validator, p string, peer BGPPeer, remote string) {
	if remote == "" || !b.internal(remote) {
		return
	}
	if peer.EBGPMultihop > 0 {
		v.addf("%s: ebgp multihop is for eBGP neighbours (an iBGP session may be multihop anyway)", p)
	}
	for _, af := range []struct {
		fam string
		s   BGPAddressFamily
	}{{"ipv4", peer.IPv4}, {"ipv6", peer.IPv6}} {
		if af.s.RemovePrivateAS {
			v.addf("%s: %s: remove private AS is for eBGP neighbours", p, af.fam)
		}
	}
}

// internal reports whether a remote AS is the local one (iBGP).
func (b *BGP) internal(remoteAS string) bool {
	if remoteAS == "internal" {
		return true
	}
	n, ok := ParseASN(remoteAS)
	return ok && n == b.ASN
}

// peerGroup returns the named peer group, or an empty one.
func (b *BGP) peerGroup(name string) BGPPeer {
	for _, g := range b.PeerGroups {
		if g.Name == name {
			return g
		}
	}
	return BGPPeer{}
}

// BGPRunning reports whether the instance runs FRR.
func (in *Instance) BGPRunning() bool {
	return in.BGP != nil && in.BGP.Enabled
}
