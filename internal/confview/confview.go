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
	"database/sql/driver"
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

	// Tree is the tree, and Index each of its entries' ids. Neither is
	// to be changed.
	Tree  *datastore.Tree
	Index sqlmap.Index
}

// ID is the id of the entry at p, if there is one.
func (v *View) ID(p datastore.Path) (uint, bool) {
	n, _, err := v.Tree.Find(p)
	if err != nil || n == nil {
		return 0, false
	}
	id, ok := v.Index[n]
	return uint(id), ok
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
	v := &View{Tree: tree, Index: idx}
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

// RowOf is the row of a model (a pointer to one of package models'
// structs): its table and its columns, as sqlmap.Adder takes them. A zero
// field with a default (gorm:"default:...") has its default, as gorm's
// Create gave it.
func RowOf(model any) (string, sqlmap.Row, error) {
	sch, err := gormschema.Parse(model, schemaCache, gormschema.NamingStrategy{})
	if err != nil {
		return "", nil, err
	}
	rv := reflect.ValueOf(model)
	for rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	ctx := context.Background()
	row := sqlmap.Row{}
	for _, f := range sch.Fields {
		if f.DBName == "" {
			continue
		}
		v, zero := f.ValueOf(ctx, rv)
		// A zero value takes the field's default, as gorm's Create gives
		// it.
		if zero && f.HasDefaultValue && f.DefaultValueInterface != nil {
			row[f.DBName] = plainValue(reflect.ValueOf(f.DefaultValueInterface))
			continue
		}
		if zero && f.FieldType.Kind() == reflect.Pointer {
			row[f.DBName] = nil
			continue
		}
		if vr, ok := v.(driver.Valuer); ok {
			if v, err = vr.Value(); err != nil {
				return "", nil, fmt.Errorf("%s.%s: %w", sch.Table, f.DBName, err)
			}
		}
		row[f.DBName] = plainValue(reflect.ValueOf(v))
	}
	return sch.Table, row, nil
}

// plainValue is v as the database driver gives a column: int64, float64,
// bool, string, []byte or nil.
func plainValue(v reflect.Value) any {
	for v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return int64(v.Uint())
	case reflect.Float32, reflect.Float64:
		return v.Float()
	case reflect.Bool:
		return v.Bool()
	case reflect.String:
		return v.String()
	}
	return v.Interface()
}

// InstanceByID is the instance with the id, nil when there is none.
func (v *View) InstanceByID(id uint) *models.Instance {
	for i := range v.Instances {
		if v.Instances[i].ID == id {
			return &v.Instances[i]
		}
	}
	return nil
}

// ByID is the row of rows with the id, nil when there is none.
func ByID[T any, PT interface {
	*T
	GetID() uint
}](rows []T, id uint) *T {
	for i := range rows {
		if PT(&rows[i]).GetID() == id {
			return &rows[i]
		}
	}
	return nil
}

// Where are the rows keep keeps, in their order.
func Where[T any](rows []T, keep func(*T) bool) []T {
	var out []T
	for i := range rows {
		if keep(&rows[i]) {
			out = append(out, rows[i])
		}
	}
	return out
}

// Of are the rows of the instance (their InstanceID), in their order.
func Of[T any](rows []T, instanceID uint) []T {
	return Where(rows, func(r *T) bool {
		return reflect.ValueOf(r).Elem().FieldByName("InstanceID").Uint() == uint64(instanceID)
	})
}

// Load sets *dst (a pointer to a model) to the row of its type with the
// id, and reports whether there is one.
func (v *View) Load(dst any, id uint) bool {
	dv := reflect.ValueOf(dst).Elem()
	rv := reflect.ValueOf(v).Elem()
	for i := range rv.NumField() {
		f := rv.Field(i)
		if f.Kind() != reflect.Slice || f.Type().Elem() != dv.Type() {
			continue
		}
		for j := range f.Len() {
			if row := f.Index(j); row.FieldByName("ID").Uint() == uint64(id) {
				dv.Set(row)
				return true
			}
		}
	}
	return false
}
