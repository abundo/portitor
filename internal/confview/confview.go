// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package confview is the configuration tree as rows: its entries decoded
// into the structs of package models, a slice per list (px:table), with
// their ids (sqlmap.IDs) and references by id. It is what the builder and
// portitor-config's code of before the tree read; there are no tables
// behind it.
package confview

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"sync"

	"gorm.io/gorm"
	gormschema "gorm.io/gorm/schema"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

// View is a tree's rows, in the tree's order (the default instance
// first), Settings its one row.
type View struct {
	Instances           []models.Instance
	InterfaceZones      []models.InterfaceZone
	Interfaces          []models.Interface
	WgPeers             []models.WgPeer
	Links               []models.Link
	Routes              []models.Route
	PolicyRoutes        []models.PolicyRoute
	StaticNeighbours    []models.StaticNeighbour
	Rules               []models.Rule
	NatRules            []models.NatRule
	IpamPrefixes        []models.IpamPrefix
	IpamAddresses       []models.IpamAddress
	DnsZones            []models.DnsZone
	DnsBlocklists       []models.DnsBlocklist
	DnsRecords          []models.DnsRecord
	AddressObjects      []models.AddressObject
	AddressLists        []models.AddressList
	ObjectFolders       []models.ObjectFolder
	DnsSoaTemplates     []models.DnsSoaTemplate
	DnsDnssecPolicies   []models.DnsDnssecPolicy
	DnsTemplates        []models.DnsTemplate
	DyndnsClients       []models.DyndnsClient
	DyndnsRecords       []models.DyndnsRecord
	Certificates        []models.Certificate
	IpLists             []models.IpList
	Tasks               []models.Task
	Services            []models.Service
	PortNames           []models.PortName
	RateLimits          []models.RateLimit
	RoutePrefixLists    []models.RoutePrefixList
	RouteAsPathLists    []models.RouteAsPathList
	RouteCommunityLists []models.RouteCommunityList
	RouteMaps           []models.RouteMap
	BgpConfigs          []models.BgpConfig
	BgpPeerGroups       []models.BgpPeerGroup
	BgpNeighbors        []models.BgpNeighbor
	OspfConfigs         []models.OspfConfig
	OspfInterfaces      []models.OspfInterface
	IsisConfigs         []models.IsisConfig
	IsisInterfaces      []models.IsisInterface
	VrrpRouters         []models.VrrpRouter
	BfdInterfaces       []models.BfdInterface
	Vrfs                []models.Vrf
	SnmpUsers           []models.SnmpUser
	SyslogServers       []models.SyslogServer
	AcmeProxyPolicies   []models.AcmeProxyPolicy
	Settings            models.Settings

	// Index is each entry's id.
	Index sqlmap.Index
}

var (
	mapOnce    sync.Once
	mapping    *sqlmap.Mapping
	mappingErr error
)

// Mapping is the schema's mapping onto rows.
func Mapping() (*sqlmap.Mapping, error) {
	mapOnce.Do(func() {
		root, err := schema.Load()
		if err != nil {
			mappingErr = err
			return
		}
		mapping, mappingErr = sqlmap.New(root)
	})
	return mapping, mappingErr
}

// Load is tree's view: the ids kept in db (sqlmap.LoadIDs), and db's ids
// of the firewalls and roles the tree names.
func Load(db *gorm.DB, tree *datastore.Tree) (*View, error) {
	ids, err := sqlmap.LoadIDs(db)
	if err != nil {
		return nil, err
	}
	return LoadWith(db, tree, ids)
}

// LoadWith is Load with ids given.
func LoadWith(db *gorm.DB, tree *datastore.Tree, ids sqlmap.IDs) (*View, error) {
	m, err := Mapping()
	if err != nil {
		return nil, err
	}
	rows, idx, err := m.Rows(db, tree, ids)
	if err != nil {
		return nil, err
	}
	v := &View{Index: idx}
	for _, q := range []struct {
		dst   any
		table string
	}{
		{&v.Instances, "instances"},
		{&v.InterfaceZones, "interface_zones"},
		{&v.Interfaces, "interfaces"},
		{&v.WgPeers, "wg_peers"},
		{&v.Links, "links"},
		{&v.Routes, "routes"},
		{&v.PolicyRoutes, "policy_routes"},
		{&v.StaticNeighbours, "static_neighbours"},
		{&v.Rules, "rules"},
		{&v.NatRules, "nat_rules"},
		{&v.IpamPrefixes, "ipam_prefixes"},
		{&v.IpamAddresses, "ipam_addresses"},
		{&v.DnsZones, "dns_zones"},
		{&v.DnsBlocklists, "dns_blocklists"},
		{&v.DnsRecords, "dns_records"},
		{&v.AddressObjects, "address_objects"},
		{&v.AddressLists, "address_lists"},
		{&v.ObjectFolders, "object_folders"},
		{&v.DnsSoaTemplates, "dns_soa_templates"},
		{&v.DnsDnssecPolicies, "dns_dnssec_policies"},
		{&v.DnsTemplates, "dns_templates"},
		{&v.DyndnsClients, "dyndns_clients"},
		{&v.DyndnsRecords, "dyndns_records"},
		{&v.Certificates, "certificates"},
		{&v.IpLists, "ip_lists"},
		{&v.Tasks, "tasks"},
		{&v.Services, "services"},
		{&v.PortNames, "port_names"},
		{&v.RateLimits, "rate_limits"},
		{&v.RoutePrefixLists, "route_prefix_lists"},
		{&v.RouteAsPathLists, "route_as_path_lists"},
		{&v.RouteCommunityLists, "route_community_lists"},
		{&v.RouteMaps, "route_maps"},
		{&v.BgpConfigs, "bgp_configs"},
		{&v.BgpPeerGroups, "bgp_peer_groups"},
		{&v.BgpNeighbors, "bgp_neighbors"},
		{&v.OspfConfigs, "ospf_configs"},
		{&v.OspfInterfaces, "ospf_interfaces"},
		{&v.IsisConfigs, "isis_configs"},
		{&v.IsisInterfaces, "isis_interfaces"},
		{&v.VrrpRouters, "vrrp_routers"},
		{&v.BfdInterfaces, "bfd_interfaces"},
		{&v.Vrfs, "vrfs"},
		{&v.SnmpUsers, "snmp_users"},
		{&v.SyslogServers, "syslog_servers"},
		{&v.AcmeProxyPolicies, "acme_proxy_policies"},
	} {
		if err := DecodeRows(rows[q.table], q.dst); err != nil {
			return nil, fmt.Errorf("%s: %w", q.table, err)
		}
	}
	var settings []models.Settings
	if err := DecodeRows(rows["settings"], &settings); err != nil {
		return nil, fmt.Errorf("settings: %w", err)
	}
	if len(settings) > 0 {
		v.Settings = settings[0]
	}
	// The default instance first.
	slices.SortStableFunc(v.Instances, func(a, b models.Instance) int {
		switch {
		case a.IsDefault == b.IsDefault:
			return 0
		case a.IsDefault:
			return -1
		}
		return 1
	})
	return v, nil
}

// Copy is a copy of v whose slices may be changed (sorted, appended to,
// their elements' fields set) without changing v's. The elements' own
// slices and maps are still shared.
func (v *View) Copy() *View {
	c := *v
	rv := reflect.ValueOf(&c).Elem()
	for i := range rv.NumField() {
		f := rv.Field(i)
		if f.Kind() == reflect.Slice && !f.IsNil() {
			n := reflect.MakeSlice(f.Type(), f.Len(), f.Len())
			reflect.Copy(n, f)
			f.Set(n)
		}
	}
	return &c
}

var schemaCache = &sync.Map{}

// DecodeRows decodes rows into the models of the slice dst points at, by
// their columns.
func DecodeRows(rows []sqlmap.Row, dst any) error {
	sv := reflect.ValueOf(dst).Elem()
	et := sv.Type().Elem()
	sch, err := gormschema.Parse(reflect.New(et).Interface(), schemaCache, gormschema.NamingStrategy{})
	if err != nil {
		return err
	}
	ctx := context.Background()
	for _, r := range rows {
		v := reflect.New(et).Elem()
		for col, val := range r {
			f := sch.LookUpField(col)
			if f == nil || f.DBName == "" {
				continue
			}
			if s, ok := val.(string); ok && f.FieldType.Kind() == reflect.Slice && f.FieldType.Elem().Kind() != reflect.Uint8 {
				// A JSON column: the models' list types scan their text.
				if sc, ok := reflect.New(f.FieldType).Interface().(interface{ Scan(any) error }); ok {
					if err := sc.Scan(s); err != nil {
						return fmt.Errorf("%s: %w", col, err)
					}
					if err := f.Set(ctx, v, reflect.ValueOf(sc).Elem().Interface()); err != nil {
						return fmt.Errorf("%s: %w", col, err)
					}
					continue
				}
			}
			if err := f.Set(ctx, v, val); err != nil {
				return fmt.Errorf("%s: %w", col, err)
			}
		}
		sv.Set(reflect.Append(sv, v))
	}
	return nil
}
