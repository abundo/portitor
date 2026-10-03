// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Routing policy objects (prefix lists, AS path lists, community lists,
// route maps) and BGP, per instance. They refer to each other by name:
// renaming an object rewrites the references to it, deleting one in use
// is refused, and a row can't move to another instance.

// Kinds of routing references.
const (
	refPrefixList = "prefix list"
	refASPath     = "as path list"
	refCommunity  = "community list"
	refRouteMap   = "route map"
	refPeerGroup  = "peer group"
)

func problems(list []string) error {
	if len(list) == 0 {
		return nil
	}
	if len(list) > 5 {
		list = append(list[:5], "...")
	}
	return bad(strings.Join(list, "; "))
}

// nextSeq numbers entries without a sequence number after the highest one,
// in steps of 5 as FRR does, and sorts them.
func nextSeq[T any](entries []T, seq func(*T) *int) {
	high := 0
	for i := range entries {
		high = max(high, *seq(&entries[i]))
	}
	for i := range entries {
		if s := seq(&entries[i]); *s == 0 {
			high += 5
			*s = high
		}
	}
	slices.SortStableFunc(entries, func(a, b T) int { return cmp.Compare(*seq(&a), *seq(&b)) })
}

func preparePrefixList(tx *gorm.DB, l, old *models.RoutePrefixList) error {
	if old != nil {
		l.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, l.InstanceID); err != nil {
		return err
	}
	l.Name = strings.TrimSpace(l.Name)
	l.Description = strings.TrimSpace(l.Description)
	if l.Family == "" {
		l.Family = "ipv4"
	}
	if l.Entries == nil {
		l.Entries = models.JSONList[fwconfig.PrefixListEntry]{}
	}
	for i := range l.Entries {
		e := &l.Entries[i]
		e.Prefix = strings.TrimSpace(e.Prefix)
		if p, err := netip.ParsePrefix(e.Prefix); err == nil {
			e.Prefix = p.Masked().String()
		}
	}
	nextSeq(l.Entries, func(e *fwconfig.PrefixListEntry) *int { return &e.Seq })
	if err := problems(fwconfig.CheckPrefixList(fwconfig.PrefixList{Name: l.Name, Family: l.Family, Description: l.Description, Entries: l.Entries})); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	if old.Family != l.Family {
		if users, err := routingUsers(tx, l.InstanceID, refPrefixList, old.Name); err != nil {
			return err
		} else if len(users) > 0 {
			return bad(fmt.Sprintf("%s is used by %s, which expect an %s list", old.Name, strings.Join(users, ", "), old.Family))
		}
	}
	return renameRoutingRef(tx, l.InstanceID, refPrefixList, old.Name, l.Name)
}

func prepareAsPathList(tx *gorm.DB, l, old *models.RouteAsPathList) error {
	if old != nil {
		l.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, l.InstanceID); err != nil {
		return err
	}
	l.Name = strings.TrimSpace(l.Name)
	l.Description = strings.TrimSpace(l.Description)
	if l.Entries == nil {
		l.Entries = models.JSONList[fwconfig.ASPathEntry]{}
	}
	for i := range l.Entries {
		l.Entries[i].Regex = strings.TrimSpace(l.Entries[i].Regex)
	}
	if err := problems(fwconfig.CheckASPathList(fwconfig.ASPathList{Name: l.Name, Description: l.Description, Entries: l.Entries})); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	return renameRoutingRef(tx, l.InstanceID, refASPath, old.Name, l.Name)
}

func prepareCommunityList(tx *gorm.DB, l, old *models.RouteCommunityList) error {
	if old != nil {
		l.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, l.InstanceID); err != nil {
		return err
	}
	l.Name = strings.TrimSpace(l.Name)
	l.Description = strings.TrimSpace(l.Description)
	if l.Kind == "" {
		l.Kind = fwconfig.CommunityStandard
	}
	if l.Entries == nil {
		l.Entries = models.JSONList[fwconfig.CommunityEntry]{}
	}
	for i := range l.Entries {
		l.Entries[i].Value = strings.TrimSpace(l.Entries[i].Value)
		if l.Kind == fwconfig.CommunityStandard || l.Kind == fwconfig.CommunityLargeStandard {
			l.Entries[i].Value = strings.Join(strings.Fields(l.Entries[i].Value), " ")
		}
	}
	if err := problems(fwconfig.CheckCommunityList(fwconfig.CommunityList{Name: l.Name, Kind: l.Kind, Description: l.Description, Entries: l.Entries})); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	return renameRoutingRef(tx, l.InstanceID, refCommunity, old.Name, l.Name)
}

func prepareRouteMap(tx *gorm.DB, m, old *models.RouteMap) error {
	if old != nil {
		m.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, m.InstanceID); err != nil {
		return err
	}
	m.Name = strings.TrimSpace(m.Name)
	m.Description = strings.TrimSpace(m.Description)
	if m.Entries == nil {
		m.Entries = models.JSONList[fwconfig.RouteMapEntry]{}
	}
	for i := range m.Entries {
		e := &m.Entries[i]
		for _, f := range []*string{&e.Description, &e.MatchPrefixList, &e.MatchNextHop, &e.MatchASPath, &e.MatchCommunity, &e.SetNextHop, &e.SetOrigin} {
			*f = strings.TrimSpace(*f)
		}
		for _, f := range []*string{&e.SetASPathPrepend, &e.SetCommunity, &e.SetLargeCommunity} {
			*f = strings.Join(strings.Fields(*f), " ")
		}
		if e.Action == fwconfig.Deny {
			// A deny sets nothing: keep its matches only.
			*e = fwconfig.RouteMapEntry{
				Seq: e.Seq, Action: e.Action, Description: e.Description,
				MatchPrefixList: e.MatchPrefixList, MatchNextHop: e.MatchNextHop, MatchASPath: e.MatchASPath,
				MatchCommunity: e.MatchCommunity, MatchMetric: e.MatchMetric, MatchTag: e.MatchTag,
			}
		}
	}
	nextSeq(m.Entries, func(e *fwconfig.RouteMapEntry) *int { return &e.Seq })
	if err := problems(fwconfig.CheckRouteMap(fwconfig.RouteMap{Name: m.Name, Description: m.Description, Entries: m.Entries})); err != nil {
		return err
	}
	o, err := loadRoutingObjects(tx, m.InstanceID)
	if err != nil {
		return err
	}
	var errs []string
	for _, e := range m.Entries {
		p := fmt.Sprintf("entry %d", e.Seq)
		errs = append(errs, o.check(p, refPrefixList, e.MatchPrefixList, "")...)
		errs = append(errs, o.check(p, refPrefixList, e.MatchNextHop, "")...)
		errs = append(errs, o.check(p, refASPath, e.MatchASPath, "")...)
		errs = append(errs, o.check(p, refCommunity, e.MatchCommunity, "")...)
	}
	if err := problems(errs); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	return renameRoutingRef(tx, m.InstanceID, refRouteMap, old.Name, m.Name)
}

func prepareBgpConfig(tx *gorm.DB, c, old *models.BgpConfig) error {
	if old != nil {
		c.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, c.InstanceID); err != nil {
		return err
	}
	c.RouterID = strings.TrimSpace(c.RouterID)
	if c.RouterID != "" {
		if a, err := netip.ParseAddr(c.RouterID); err != nil || !a.Is4() {
			return bad("router id must be an IPv4 address (e.g. 192.0.2.1)")
		}
	}
	if c.Enabled && c.Asn == 0 {
		return bad("local AS is required (1-4294967295)")
	}
	if !fwconfig.ValidBGPTimers(c.Keepalive, c.Hold) {
		return bad("timers: keepalive 1-65535, hold 3-65535 and not less than keepalive (0 keeps FRR's)")
	}
	if c.MaximumPaths < 0 || c.MaximumPaths > 128 {
		return bad("maximum paths: 1-128 (0 keeps FRR's)")
	}
	if c.Networks == nil {
		c.Networks = models.JSONList[fwconfig.BGPNetwork]{}
	}
	if c.Aggregates == nil {
		c.Aggregates = models.JSONList[fwconfig.BGPAggregate]{}
	}
	o, err := loadRoutingObjects(tx, c.InstanceID)
	if err != nil {
		return err
	}
	var errs []string
	seen := map[string]bool{}
	for i := range c.Networks {
		n := &c.Networks[i]
		p, err := netip.ParsePrefix(strings.TrimSpace(n.Prefix))
		if err != nil {
			return bad(fmt.Sprintf("network %q is not a prefix (e.g. 192.0.2.0/24)", n.Prefix))
		}
		n.Prefix = p.Masked().String()
		if seen[n.Prefix] {
			return bad(fmt.Sprintf("network %s is listed twice", n.Prefix))
		}
		seen[n.Prefix] = true
		errs = append(errs, o.check("network "+n.Prefix, refRouteMap, n.RouteMap, "")...)
	}
	seen = map[string]bool{}
	for i := range c.Aggregates {
		a := &c.Aggregates[i]
		p, err := netip.ParsePrefix(strings.TrimSpace(a.Prefix))
		if err != nil {
			return bad(fmt.Sprintf("aggregate address %q is not a prefix", a.Prefix))
		}
		a.Prefix = p.Masked().String()
		if seen[a.Prefix] {
			return bad(fmt.Sprintf("aggregate address %s is listed twice", a.Prefix))
		}
		seen[a.Prefix] = true
	}
	for _, r := range []struct {
		what  string
		on    bool
		value *string
	}{
		{"redistribute connected (IPv4)", c.RedistConnectedV4, &c.RedistConnectedV4Map},
		{"redistribute static (IPv4)", c.RedistStaticV4, &c.RedistStaticV4Map},
		{"redistribute connected (IPv6)", c.RedistConnectedV6, &c.RedistConnectedV6Map},
		{"redistribute static (IPv6)", c.RedistStaticV6, &c.RedistStaticV6Map},
	} {
		if !r.on {
			*r.value = ""
		}
		errs = append(errs, o.check(r.what, refRouteMap, *r.value, "")...)
	}
	return problems(errs)
}

// preparePeerSettings checks what a neighbour and a peer group have in
// common, and takes a new password.
func preparePeerSettings(tx *gorm.DB, instanceID uint, s, old *models.BgpPeerSettings, peer fwconfig.BGPPeer) error {
	s.Description = strings.TrimSpace(s.Description)
	s.RemoteAs = strings.TrimSpace(s.RemoteAs)
	s.UpdateSource = strings.TrimSpace(s.UpdateSource)
	switch {
	case s.ClearPassword:
		s.Password = ""
	case s.NewPassword != "":
		s.Password = s.NewPassword
	case old != nil:
		s.Password = old.Password
	}
	s.NewPassword, s.ClearPassword = "", false
	peer.Description, peer.RemoteAS, peer.UpdateSource, peer.Password = s.Description, s.RemoteAs, s.UpdateSource, s.Password
	if !s.V4Activate {
		s.V4PrefixListIn, s.V4PrefixListOut, s.V4RouteMapIn, s.V4RouteMapOut = "", "", "", ""
	}
	if !s.V6Activate {
		s.V6PrefixListIn, s.V6PrefixListOut, s.V6RouteMapIn, s.V6RouteMapOut = "", "", "", ""
	}
	full := s.Peer()
	full.Name, full.Address, full.PeerGroup = peer.Name, peer.Address, peer.PeerGroup
	if err := problems(fwconfig.CheckBGPPeer(full)); err != nil {
		return err
	}
	if s.UpdateSource != "" {
		if _, err := fwconfig.ParseAddr(s.UpdateSource); err != nil {
			var n int64
			tx.Model(&models.Interface{}).Where("instance_id = ? AND name = ?", instanceID, s.UpdateSource).Count(&n)
			if n == 0 {
				return bad(fmt.Sprintf("update source %q is neither an address nor an interface of this virtual firewall", s.UpdateSource))
			}
		}
	}
	o, err := loadRoutingObjects(tx, instanceID)
	if err != nil {
		return err
	}
	var errs []string
	lists, maps := s.PolicyRefs()
	for what, ref := range lists {
		errs = append(errs, o.check(what, refPrefixList, *ref, strings.Fields(what)[0])...)
	}
	for _, ref := range maps {
		errs = append(errs, o.check("filter", refRouteMap, *ref, "")...)
	}
	slices.Sort(errs)
	return problems(errs)
}

func preparePeerGroup(tx *gorm.DB, g, old *models.BgpPeerGroup) error {
	if old != nil {
		g.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, g.InstanceID); err != nil {
		return err
	}
	g.Name = strings.TrimSpace(g.Name)
	var oldSettings *models.BgpPeerSettings
	if old != nil {
		oldSettings = &old.BgpPeerSettings
	}
	if err := preparePeerSettings(tx, g.InstanceID, &g.BgpPeerSettings, oldSettings, fwconfig.BGPPeer{Name: g.Name}); err != nil {
		return err
	}
	if err := checkSession(tx, g.InstanceID, g.Peer(), g.RemoteAs); err != nil {
		return err
	}
	if old == nil {
		return nil
	}
	return renameRoutingRef(tx, g.InstanceID, refPeerGroup, old.Name, g.Name)
}

func prepareNeighbor(tx *gorm.DB, n, old *models.BgpNeighbor) error {
	if old != nil {
		n.InstanceID = old.InstanceID // rows stay in their instance
	}
	if err := instanceExists(tx, n.InstanceID); err != nil {
		return err
	}
	a, err := fwconfig.ParseAddr(strings.TrimSpace(n.Address))
	if err != nil {
		return bad("address must be an IPv4 or IPv6 address")
	}
	n.Address = a.String()
	n.PeerGroup = strings.TrimSpace(n.PeerGroup)
	var group *models.BgpPeerGroup
	if n.PeerGroup != "" {
		group = &models.BgpPeerGroup{}
		if err := tx.Where("instance_id = ? AND name = ?", n.InstanceID, n.PeerGroup).First(group).Error; err != nil {
			return bad(fmt.Sprintf("peer group %q does not exist", n.PeerGroup))
		}
	}
	var oldSettings *models.BgpPeerSettings
	if old != nil {
		oldSettings = &old.BgpPeerSettings
	}
	if err := preparePeerSettings(tx, n.InstanceID, &n.BgpPeerSettings, oldSettings, fwconfig.BGPPeer{Address: n.Address, PeerGroup: n.PeerGroup}); err != nil {
		return err
	}
	remote := n.RemoteAs
	if remote == "" && group != nil {
		remote = group.RemoteAs
	}
	if remote == "" {
		return bad("remote AS is required (on the neighbour or its peer group)")
	}
	return checkSession(tx, n.InstanceID, n.Peer(), remote)
}

// checkSession checks a neighbour or peer group against the instance's
// local AS (fwconfig.CheckBGPSession).
func checkSession(tx *gorm.DB, instanceID uint, peer fwconfig.BGPPeer, remote string) error {
	var asn uint32
	tx.Model(&models.BgpConfig{}).Where("instance_id = ?", instanceID).Pluck("asn", &asn)
	return problems(fwconfig.CheckBGPSession(asn, peer, remote))
}

func presentPeerGroup(g *models.BgpPeerGroup) { presentPeerSettings(&g.BgpPeerSettings) }
func presentNeighbor(n *models.BgpNeighbor)   { presentPeerSettings(&n.BgpPeerSettings) }

func presentPeerSettings(s *models.BgpPeerSettings) {
	s.HasPassword = s.Password != ""
	s.NewPassword, s.ClearPassword = "", false
}

// routingObjects are the names of an instance's routing objects.
type routingObjects struct {
	prefixLists map[string]string // name -> family
	names       map[string]map[string]bool
}

func loadRoutingObjects(tx *gorm.DB, instanceID uint) (*routingObjects, error) {
	o := &routingObjects{prefixLists: map[string]string{}, names: map[string]map[string]bool{}}
	var pls []models.RoutePrefixList
	if err := tx.Select("name", "family").Where("instance_id = ?", instanceID).Find(&pls).Error; err != nil {
		return nil, err
	}
	for _, pl := range pls {
		o.prefixLists[pl.Name] = pl.Family
	}
	for kind, table := range map[string]string{refASPath: "route_as_path_lists", refCommunity: "route_community_lists", refRouteMap: "route_maps"} {
		var names []string
		if err := tx.Table(table).Where("instance_id = ?", instanceID).Pluck("name", &names).Error; err != nil {
			return nil, err
		}
		o.names[kind] = map[string]bool{}
		for _, n := range names {
			o.names[kind][n] = true
		}
	}
	return o, nil
}

// check reports a reference to an object that does not exist, or (with
// family) a prefix list of the other IP version.
func (o *routingObjects) check(where, kind, name, family string) []string {
	if name == "" {
		return nil
	}
	if kind == refPrefixList {
		fam, ok := o.prefixLists[name]
		switch {
		case !ok:
			return []string{fmt.Sprintf("%s: prefix list %q does not exist", where, name)}
		case family != "" && fam != family:
			return []string{fmt.Sprintf("%s: prefix list %s is %s", where, name, fam)}
		}
		return nil
	}
	if !o.names[kind][name] {
		return []string{fmt.Sprintf("%s: %s %q does not exist", where, kind, name)}
	}
	return nil
}

// eachRoutingRef calls visit for every reference of an instance's route
// maps, BGP config, peer groups and neighbours to a routing object (or a
// neighbour's to its peer group). Rows where visit changed one are saved.
func eachRoutingRef(tx *gorm.DB, instanceID uint, visit func(kind, where string, ref *string) bool) error {
	var maps []models.RouteMap
	if err := tx.Where("instance_id = ?", instanceID).Find(&maps).Error; err != nil {
		return err
	}
	for _, m := range maps {
		changed := false
		for i := range m.Entries {
			e := &m.Entries[i]
			where := fmt.Sprintf("route map %s entry %d", m.Name, e.Seq)
			for _, r := range []struct {
				kind string
				ref  *string
			}{{refPrefixList, &e.MatchPrefixList}, {refPrefixList, &e.MatchNextHop}, {refASPath, &e.MatchASPath}, {refCommunity, &e.MatchCommunity}} {
				if *r.ref != "" && visit(r.kind, where, r.ref) {
					changed = true
				}
			}
		}
		if changed {
			if err := tx.Model(&models.RouteMap{}).Where("id = ?", m.ID).UpdateColumn("entries", m.Entries).Error; err != nil {
				return err
			}
		}
	}

	var cfgs []models.BgpConfig
	if err := tx.Where("instance_id = ?", instanceID).Find(&cfgs).Error; err != nil {
		return err
	}
	for _, c := range cfgs {
		changed := false
		for i := range c.Networks {
			if c.Networks[i].RouteMap != "" && visit(refRouteMap, "BGP network "+c.Networks[i].Prefix, &c.Networks[i].RouteMap) {
				changed = true
			}
		}
		for _, r := range []*string{&c.RedistConnectedV4Map, &c.RedistStaticV4Map, &c.RedistConnectedV6Map, &c.RedistStaticV6Map} {
			if *r != "" && visit(refRouteMap, "BGP redistribute", r) {
				changed = true
			}
		}
		if changed {
			if err := tx.Model(&models.BgpConfig{}).Where("id = ?", c.ID).Select("networks", "redist_connected_v4_map", "redist_static_v4_map", "redist_connected_v6_map", "redist_static_v6_map").Updates(&c).Error; err != nil {
				return err
			}
		}
	}

	visitPeer := func(where string, s *models.BgpPeerSettings) bool {
		changed := false
		lists, maps := s.PolicyRefs()
		for _, ref := range lists {
			if *ref != "" && visit(refPrefixList, where, ref) {
				changed = true
			}
		}
		for _, ref := range maps {
			if *ref != "" && visit(refRouteMap, where, ref) {
				changed = true
			}
		}
		return changed
	}
	peerColumns := []string{"v4_prefix_list_in", "v4_prefix_list_out", "v6_prefix_list_in", "v6_prefix_list_out", "v4_route_map_in", "v4_route_map_out", "v6_route_map_in", "v6_route_map_out"}
	var groups []models.BgpPeerGroup
	if err := tx.Where("instance_id = ?", instanceID).Find(&groups).Error; err != nil {
		return err
	}
	for _, g := range groups {
		if visitPeer("BGP peer group "+g.Name, &g.BgpPeerSettings) {
			if err := tx.Model(&models.BgpPeerGroup{}).Where("id = ?", g.ID).Select(peerColumns).Updates(&g).Error; err != nil {
				return err
			}
		}
	}
	var neighbors []models.BgpNeighbor
	if err := tx.Where("instance_id = ?", instanceID).Find(&neighbors).Error; err != nil {
		return err
	}
	for _, n := range neighbors {
		where := "BGP neighbour " + n.Address
		changed := visitPeer(where, &n.BgpPeerSettings)
		if n.PeerGroup != "" && visit(refPeerGroup, where, &n.PeerGroup) {
			changed = true
		}
		if changed {
			if err := tx.Model(&models.BgpNeighbor{}).Where("id = ?", n.ID).Select(append(slices.Clone(peerColumns), "peer_group")).Updates(&n).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func renameRoutingRef(tx *gorm.DB, instanceID uint, kind, from, to string) error {
	if from == to {
		return nil
	}
	return eachRoutingRef(tx, instanceID, func(k, _ string, ref *string) bool {
		if k == kind && *ref == from {
			*ref = to
			return true
		}
		return false
	})
}

// routingUsers lists what refers to an object.
func routingUsers(tx *gorm.DB, instanceID uint, kind, name string) ([]string, error) {
	var users []string
	err := eachRoutingRef(tx, instanceID, func(k, where string, ref *string) bool {
		if k == kind && *ref == name && !slices.Contains(users, where) {
			users = append(users, where)
		}
		return false
	})
	return users, err
}

func refuseInUse(tx *gorm.DB, instanceID uint, kind, name string) error {
	users, err := routingUsers(tx, instanceID, kind, name)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		if len(users) > 5 {
			users = append(users[:5], "...")
		}
		return bad(fmt.Sprintf("%s %s is used by %s", kind, name, strings.Join(users, ", ")))
	}
	return nil
}

func deletePrefixList(tx *gorm.DB, l *models.RoutePrefixList) error {
	return refuseInUse(tx, l.InstanceID, refPrefixList, l.Name)
}

func deleteAsPathList(tx *gorm.DB, l *models.RouteAsPathList) error {
	return refuseInUse(tx, l.InstanceID, refASPath, l.Name)
}

func deleteCommunityList(tx *gorm.DB, l *models.RouteCommunityList) error {
	return refuseInUse(tx, l.InstanceID, refCommunity, l.Name)
}

func deleteRouteMap(tx *gorm.DB, m *models.RouteMap) error {
	return refuseInUse(tx, m.InstanceID, refRouteMap, m.Name)
}

func deletePeerGroup(tx *gorm.DB, g *models.BgpPeerGroup) error {
	return refuseInUse(tx, g.InstanceID, refPeerGroup, g.Name)
}
