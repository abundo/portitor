// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"

	"github.com/abundo/portitor/internal/fwconfig"
)

// JSONList is stored as a JSON array in a TEXT column.
type JSONList[T any] []T

func (l JSONList[T]) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]T(l))
	return string(b), err
}

func (l *JSONList[T]) Scan(src any) error {
	var data []byte
	switch v := src.(type) {
	case nil:
		*l = JSONList[T]{}
		return nil
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("JSONList: unsupported type")
	}
	var out []T
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*l = out
	return nil
}

func (l JSONList[T]) MarshalJSON() ([]byte, error) {
	if l == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]T(l))
}

func (JSONList[T]) GormDataType() string { return "text" }

// Routing policy objects of an instance (Network > Routing > Routing
// objects). BGP and route maps refer to them by name; renaming one
// rewrites those references, and one in use can't be deleted.

type RoutePrefixList struct {
	Base
	InstanceID  uint                               `json:"instance_id"`
	Name        string                             `json:"name"`
	Family      string                             `json:"family"` // ipv4, ipv6
	Description string                             `json:"description"`
	Entries     JSONList[fwconfig.PrefixListEntry] `json:"entries"`
}

type RouteAsPathList struct {
	Base
	InstanceID  uint                           `json:"instance_id"`
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Entries     JSONList[fwconfig.ASPathEntry] `json:"entries"`
}

type RouteCommunityList struct {
	Base
	InstanceID  uint                              `json:"instance_id"`
	Name        string                            `json:"name"`
	Kind        string                            `json:"kind"` // fwconfig.Community*
	Description string                            `json:"description"`
	Entries     JSONList[fwconfig.CommunityEntry] `json:"entries"`
}

type RouteMap struct {
	Base
	InstanceID  uint                             `json:"instance_id"`
	Name        string                           `json:"name"`
	Description string                           `json:"description"`
	Entries     JSONList[fwconfig.RouteMapEntry] `json:"entries"`
}

// BgpConfig is an instance's BGP: one row per instance, made on the first
// save. BGP is off (FRR stopped) until Enabled.
type BgpConfig struct {
	Base
	InstanceID         uint                            `json:"instance_id"`
	Enabled            bool                            `json:"enabled"`
	Asn                uint32                          `json:"asn"`
	RouterID           string                          `json:"router_id"`
	Keepalive          int                             `json:"keepalive"`
	Hold               int                             `json:"hold"`
	EbgpRequiresPolicy bool                            `json:"ebgp_requires_policy"`
	LogNeighborChanges bool                            `json:"log_neighbor_changes"`
	GracefulRestart    bool                            `json:"graceful_restart"`
	MultipathRelax     bool                            `json:"multipath_relax"`
	MaximumPaths       int                             `json:"maximum_paths"`
	Networks           JSONList[fwconfig.BGPNetwork]   `json:"networks"`
	Aggregates         JSONList[fwconfig.BGPAggregate] `json:"aggregates"`
	// Redistribution of connected networks and static routes per IP
	// version, each with an optional route map.
	RedistConnectedV4    bool   `gorm:"column:redist_connected_v4" json:"redist_connected_v4"`
	RedistConnectedV4Map string `gorm:"column:redist_connected_v4_map" json:"redist_connected_v4_map"`
	RedistStaticV4       bool   `gorm:"column:redist_static_v4" json:"redist_static_v4"`
	RedistStaticV4Map    string `gorm:"column:redist_static_v4_map" json:"redist_static_v4_map"`
	RedistConnectedV6    bool   `gorm:"column:redist_connected_v6" json:"redist_connected_v6"`
	RedistConnectedV6Map string `gorm:"column:redist_connected_v6_map" json:"redist_connected_v6_map"`
	RedistStaticV6       bool   `gorm:"column:redist_static_v6" json:"redist_static_v6"`
	RedistStaticV6Map    string `gorm:"column:redist_static_v6_map" json:"redist_static_v6_map"`
	// OSPFv2's routes into IPv4, OSPFv3's into IPv6.
	RedistOspfV4    bool   `gorm:"column:redist_ospf_v4" json:"redist_ospf_v4"`
	RedistOspfV4Map string `gorm:"column:redist_ospf_v4_map" json:"redist_ospf_v4_map"`
	RedistOspfV6    bool   `gorm:"column:redist_ospf_v6" json:"redist_ospf_v6"`
	RedistOspfV6Map string `gorm:"column:redist_ospf_v6_map" json:"redist_ospf_v6_map"`
}

// BgpPeerSettings are what a neighbour and a peer group both have.
type BgpPeerSettings struct {
	Description  string `json:"description"`
	RemoteAs     string `json:"remote_as"` // AS number, internal, external
	Password     string `json:"-"`
	EbgpMultihop int    `json:"ebgp_multihop"` // TTL; 0 off
	UpdateSource string `json:"update_source"`
	Passive      bool   `json:"passive"`
	Shutdown     bool   `json:"shutdown"`
	Keepalive    int    `json:"keepalive"`
	Hold         int    `json:"hold"`

	V4Activate             bool   `gorm:"column:v4_activate" json:"v4_activate"`
	V4PrefixListIn         string `gorm:"column:v4_prefix_list_in" json:"v4_prefix_list_in"`
	V4PrefixListOut        string `gorm:"column:v4_prefix_list_out" json:"v4_prefix_list_out"`
	V4RouteMapIn           string `gorm:"column:v4_route_map_in" json:"v4_route_map_in"`
	V4RouteMapOut          string `gorm:"column:v4_route_map_out" json:"v4_route_map_out"`
	V4NextHopSelf          bool   `gorm:"column:v4_next_hop_self" json:"v4_next_hop_self"`
	V4RemovePrivateAs      bool   `gorm:"column:v4_remove_private_as" json:"v4_remove_private_as"`
	V4SoftReconfiguration  bool   `gorm:"column:v4_soft_reconfiguration" json:"v4_soft_reconfiguration"`
	V4DefaultOriginate     bool   `gorm:"column:v4_default_originate" json:"v4_default_originate"`
	V4RouteReflectorClient bool   `gorm:"column:v4_route_reflector_client" json:"v4_route_reflector_client"`
	V4AllowasIn            int    `gorm:"column:v4_allowas_in" json:"v4_allowas_in"`
	V4MaximumPrefix        int    `gorm:"column:v4_maximum_prefix" json:"v4_maximum_prefix"`

	V6Activate             bool   `gorm:"column:v6_activate" json:"v6_activate"`
	V6PrefixListIn         string `gorm:"column:v6_prefix_list_in" json:"v6_prefix_list_in"`
	V6PrefixListOut        string `gorm:"column:v6_prefix_list_out" json:"v6_prefix_list_out"`
	V6RouteMapIn           string `gorm:"column:v6_route_map_in" json:"v6_route_map_in"`
	V6RouteMapOut          string `gorm:"column:v6_route_map_out" json:"v6_route_map_out"`
	V6NextHopSelf          bool   `gorm:"column:v6_next_hop_self" json:"v6_next_hop_self"`
	V6RemovePrivateAs      bool   `gorm:"column:v6_remove_private_as" json:"v6_remove_private_as"`
	V6SoftReconfiguration  bool   `gorm:"column:v6_soft_reconfiguration" json:"v6_soft_reconfiguration"`
	V6DefaultOriginate     bool   `gorm:"column:v6_default_originate" json:"v6_default_originate"`
	V6RouteReflectorClient bool   `gorm:"column:v6_route_reflector_client" json:"v6_route_reflector_client"`
	V6AllowasIn            int    `gorm:"column:v6_allowas_in" json:"v6_allowas_in"`
	V6MaximumPrefix        int    `gorm:"column:v6_maximum_prefix" json:"v6_maximum_prefix"`

	// The password is write-only: NewPassword sets it (empty keeps it),
	// ClearPassword removes it, HasPassword tells whether there is one.
	NewPassword   string `gorm:"-" json:"new_password,omitempty"`
	ClearPassword bool   `gorm:"-" json:"clear_password,omitempty"`
	HasPassword   bool   `gorm:"-" json:"has_password"`
}

// Peer is the settings as the document holds them.
func (s *BgpPeerSettings) Peer() fwconfig.BGPPeer {
	return fwconfig.BGPPeer{
		RemoteAS:     s.RemoteAs,
		Description:  s.Description,
		Password:     s.Password,
		EBGPMultihop: s.EbgpMultihop,
		UpdateSource: s.UpdateSource,
		Passive:      s.Passive,
		Shutdown:     s.Shutdown,
		Keepalive:    s.Keepalive,
		Hold:         s.Hold,
		IPv4: fwconfig.BGPAddressFamily{
			Activate: s.V4Activate, PrefixListIn: s.V4PrefixListIn, PrefixListOut: s.V4PrefixListOut,
			RouteMapIn: s.V4RouteMapIn, RouteMapOut: s.V4RouteMapOut, NextHopSelf: s.V4NextHopSelf,
			RemovePrivateAS: s.V4RemovePrivateAs, SoftReconfiguration: s.V4SoftReconfiguration,
			DefaultOriginate: s.V4DefaultOriginate, RouteReflectorClient: s.V4RouteReflectorClient,
			AllowASIn: s.V4AllowasIn, MaximumPrefix: s.V4MaximumPrefix,
		},
		IPv6: fwconfig.BGPAddressFamily{
			Activate: s.V6Activate, PrefixListIn: s.V6PrefixListIn, PrefixListOut: s.V6PrefixListOut,
			RouteMapIn: s.V6RouteMapIn, RouteMapOut: s.V6RouteMapOut, NextHopSelf: s.V6NextHopSelf,
			RemovePrivateAS: s.V6RemovePrivateAs, SoftReconfiguration: s.V6SoftReconfiguration,
			DefaultOriginate: s.V6DefaultOriginate, RouteReflectorClient: s.V6RouteReflectorClient,
			AllowASIn: s.V6AllowasIn, MaximumPrefix: s.V6MaximumPrefix,
		},
	}
}

// PolicyRefs returns pointers to the settings' prefix list and route map
// references, by IP version.
func (s *BgpPeerSettings) PolicyRefs() (prefixLists map[string]*string, routeMaps []*string) {
	return map[string]*string{
			"ipv4 prefix list in": &s.V4PrefixListIn, "ipv4 prefix list out": &s.V4PrefixListOut,
			"ipv6 prefix list in": &s.V6PrefixListIn, "ipv6 prefix list out": &s.V6PrefixListOut,
		}, []*string{
			&s.V4RouteMapIn, &s.V4RouteMapOut, &s.V6RouteMapIn, &s.V6RouteMapOut,
		}
}

type BgpPeerGroup struct {
	Base
	InstanceID uint   `json:"instance_id"`
	Name       string `json:"name"`
	BgpPeerSettings
}

// BgpNeighbor is a neighbour, in an optional peer group (by name).
type BgpNeighbor struct {
	Base
	InstanceID uint   `json:"instance_id"`
	Address    string `json:"address"`
	Enabled    bool   `json:"enabled"`
	PeerGroup  string `json:"peer_group"`
	BgpPeerSettings
}

// OspfConfig is an instance's OSPFv2 (Version 2) or OSPFv3 (3): one row
// per instance and version, made on the first save. It is off (not run)
// until Enabled.
type OspfConfig struct {
	Base
	InstanceID          uint                                `json:"instance_id"`
	Version             int                                 `json:"version"`
	Enabled             bool                                `json:"enabled"`
	RouterID            string                              `json:"router_id"`
	ReferenceBandwidth  int                                 `json:"reference_bandwidth"`
	LogAdjacencyChanges bool                                `json:"log_adjacency_changes"`
	MaximumPaths        int                                 `json:"maximum_paths"`
	DefaultOriginate    bool                                `json:"default_originate"`
	DefaultAlways       bool                                `json:"default_always"`
	Areas               JSONList[fwconfig.OSPFArea]         `json:"areas"`
	Ranges              JSONList[fwconfig.OSPFRange]        `json:"ranges"`
	Summaries           JSONList[fwconfig.OSPFSummary]      `json:"summaries"`
	Networks            JSONList[fwconfig.OSPFNetwork]      `json:"networks"` // OSPFv2 only
	Redistribute        JSONList[fwconfig.OSPFRedistribute] `json:"redistribute"`
}

// OspfInterface is OSPF on an interface of the instance, by name.
type OspfInterface struct {
	Base
	InstanceID    uint   `json:"instance_id"`
	Version       int    `json:"version"`
	Name          string `json:"name"`
	Area          string `json:"area"`
	Passive       bool   `json:"passive"`
	Cost          int    `json:"cost"`
	HelloInterval int    `json:"hello_interval"`
	DeadInterval  int    `json:"dead_interval"`
	Priority      *int   `json:"priority"`
	NetworkType   string `json:"network_type"`
	AuthKeyID     int    `json:"auth_key_id"`
	AuthKey       string `json:"-"`

	// The MD5 key (OSPFv2) is write-only: NewAuthKey sets it (empty keeps
	// it), ClearAuthKey removes it, HasAuthKey tells whether there is one.
	NewAuthKey   string `gorm:"-" json:"new_auth_key,omitempty"`
	ClearAuthKey bool   `gorm:"-" json:"clear_auth_key,omitempty"`
	HasAuthKey   bool   `gorm:"-" json:"has_auth_key"`
}

// Interface is the interface as the document holds it.
func (i *OspfInterface) Interface() fwconfig.OSPFInterface {
	return fwconfig.OSPFInterface{
		Name: i.Name, Area: i.Area, Passive: i.Passive, Cost: i.Cost,
		HelloInterval: i.HelloInterval, DeadInterval: i.DeadInterval, Priority: i.Priority,
		NetworkType: i.NetworkType, AuthKeyID: i.AuthKeyID, AuthKey: i.AuthKey,
	}
}
