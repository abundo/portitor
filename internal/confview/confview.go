// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package confview is the configuration tree as rows: its entries decoded
// into the structs of package models, a slice per list (px:table), with
// their ids (sqlmap.IDs) and references by id. It is what the builder and
// portitor-config's code of before the tree read; there are no tables
// behind it.
package confview

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"slices"
	"sync"

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
	LdapServers         []models.LdapServer
	Users               []models.User
	Firewalls           []models.Firewall
	Roles               []models.Role
	RoleMembers         []models.RoleMember
	RoleInstances       []models.RoleInstance
	LdapRoleMappings    []models.LdapRoleMapping
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

// viewTables are the View's lists and their tables, in the order they are
// decoded.
var viewTables = []struct{ field, table string }{
	{"Instances", "instances"},
	{"InterfaceZones", "interface_zones"},
	{"Interfaces", "interfaces"},
	{"WgPeers", "wg_peers"},
	{"Links", "links"},
	{"Routes", "routes"},
	{"PolicyRoutes", "policy_routes"},
	{"StaticNeighbours", "static_neighbours"},
	{"Rules", "rules"},
	{"NatRules", "nat_rules"},
	{"IpamPrefixes", "ipam_prefixes"},
	{"IpamAddresses", "ipam_addresses"},
	{"DnsZones", "dns_zones"},
	{"DnsBlocklists", "dns_blocklists"},
	{"DnsRecords", "dns_records"},
	{"AddressObjects", "address_objects"},
	{"AddressLists", "address_lists"},
	{"ObjectFolders", "object_folders"},
	{"DnsSoaTemplates", "dns_soa_templates"},
	{"DnsDnssecPolicies", "dns_dnssec_policies"},
	{"DnsTemplates", "dns_templates"},
	{"DyndnsClients", "dyndns_clients"},
	{"DyndnsRecords", "dyndns_records"},
	{"Certificates", "certificates"},
	{"IpLists", "ip_lists"},
	{"Tasks", "tasks"},
	{"Services", "services"},
	{"PortNames", "port_names"},
	{"RateLimits", "rate_limits"},
	{"RoutePrefixLists", "route_prefix_lists"},
	{"RouteAsPathLists", "route_as_path_lists"},
	{"RouteCommunityLists", "route_community_lists"},
	{"RouteMaps", "route_maps"},
	{"BgpConfigs", "bgp_configs"},
	{"BgpPeerGroups", "bgp_peer_groups"},
	{"BgpNeighbors", "bgp_neighbors"},
	{"OspfConfigs", "ospf_configs"},
	{"OspfInterfaces", "ospf_interfaces"},
	{"IsisConfigs", "isis_configs"},
	{"IsisInterfaces", "isis_interfaces"},
	{"VrrpRouters", "vrrp_routers"},
	{"BfdInterfaces", "bfd_interfaces"},
	{"Vrfs", "vrfs"},
	{"SnmpUsers", "snmp_users"},
	{"SyslogServers", "syslog_servers"},
	{"LdapServers", "ldap_servers"},
	{"Users", "users"},
	{"Firewalls", "firewalls"},
	{"Roles", "roles"},
	{"RoleMembers", "role_members"},
	{"RoleInstances", "role_instances"},
	{"LdapRoleMappings", "ldap_role_mappings"},
	{"AcmeProxyPolicies", "acme_proxy_policies"},
}

// tableOf is the table of each model type: the View's, and the settings'.
var tableOf = func() map[reflect.Type]string {
	out := map[reflect.Type]string{reflect.TypeFor[models.Settings](): "settings"}
	vt := reflect.TypeFor[View]()
	for _, q := range viewTables {
		f, ok := vt.FieldByName(q.field)
		if !ok {
			panic("confview: View has no " + q.field)
		}
		out[f.Type.Elem()] = q.table
	}
	return out
}()

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
func Load(src sqlmap.Source, tree *datastore.Tree) (*View, error) {
	ids, err := src.IDs()
	if err != nil {
		return nil, err
	}
	return LoadWith(tree, ids)
}

// LoadWith is Load with ids given.
func LoadWith(tree *datastore.Tree, ids sqlmap.IDs) (*View, error) {
	m, err := Mapping()
	if err != nil {
		return nil, err
	}
	rows, idx, err := m.Rows(tree, ids)
	if err != nil {
		return nil, err
	}
	v := &View{Tree: tree, Index: idx}
	rv := reflect.ValueOf(v).Elem()
	for _, q := range viewTables {
		if err := DecodeRows(rows[q.table], rv.FieldByName(q.field).Addr().Interface()); err != nil {
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

// DecodeRows decodes rows into the models of the slice dst points at, by
// their columns (fields.go).
func DecodeRows(rows []sqlmap.Row, dst any) error {
	sv := reflect.ValueOf(dst).Elem()
	et := sv.Type().Elem()
	info := infoOf(et)
	for _, r := range rows {
		v := reflect.New(et).Elem()
		for col, val := range r {
			f := info.byColumn[col]
			if f == nil {
				continue
			}
			if err := setField(v.FieldByIndex(f.index), val); err != nil {
				return fmt.Errorf("%s: %w", col, err)
			}
		}
		sv.Set(reflect.Append(sv, v))
	}
	return nil
}

// RowOf is the row of a model (a pointer to one of package models'
// structs): its table and its columns, as sqlmap.Adder takes them. A zero
// field with a default (gorm:"default:...") has its default.
func RowOf(model any) (string, sqlmap.Row, error) {
	rv := reflect.ValueOf(model)
	for rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	table, ok := tableOf[rv.Type()]
	if !ok {
		return "", nil, fmt.Errorf("%s is no list of the configuration", rv.Type())
	}
	info := infoOf(rv.Type())
	row := sqlmap.Row{}
	for i := range info.fields {
		f := &info.fields[i]
		fv := rv.FieldByIndex(f.index)
		if fv.IsZero() && f.hasDef {
			v, err := defaultValue(f)
			if err != nil {
				return "", nil, fmt.Errorf("%s.%s: %w", table, f.column, err)
			}
			row[f.column] = v
			continue
		}
		if fv.Kind() == reflect.Pointer && fv.IsNil() {
			row[f.column] = nil
			continue
		}
		v := fv.Interface()
		if vr, ok := v.(driver.Valuer); ok {
			var err error
			if v, err = vr.Value(); err != nil {
				return "", nil, fmt.Errorf("%s.%s: %w", table, f.column, err)
			}
		}
		row[f.column] = plainValue(reflect.ValueOf(v))
	}
	return table, row, nil
}

// Columns are the columns of a model type (a pointer to one of package
// models' structs), with its table.
func Columns(model any) (string, []string) {
	t := reflect.TypeOf(model)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var cols []string
	for _, f := range infoOf(t).fields {
		cols = append(cols, f.column)
	}
	return tableOf[t], cols
}

// plainValue is v as a row's column holds it: int64, float64,
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
