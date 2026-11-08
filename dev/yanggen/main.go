// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command yanggen wrote the first draft of the YANG modules in yang/ from the
// SQLite schema (the goose migrations), the models' comments and the table
// spec below. It was run once; the modules are the source now and are edited
// by hand. It stays for reference while the tables exist (see
// dev/design-model-driven.md), and to check a draft of a new table:
//
//	go run ./dev/yanggen -out /tmp/yang
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"

	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// A table is one SQL table as a YANG list (or the settings container).
type table struct {
	sql     string
	list    string
	module  string // submodule, by area
	parent  string // parent list's table; "" is top level, "instances" per instance
	parCol  string // column of the parent's id
	key     []string
	ordered string // position column of an ordered-by user list
	model   any
	refs    map[string]string // column → YANG type body (leafref and unions)
	enums   map[string][]string
	ids     map[string]idRef // id columns
	json    map[string]jsonList
	secret  []string
	skip    []string
	desc    string
}

// An idRef is a column holding another row's id, written as the leaf name
// and its reference.
type idRef struct {
	leaf     string
	path     string // leafref path
	external string // or a table outside the datastore, by name
	global   string // or a name of the instance's entries, or global ones
	null     string // the value that stands for NULL
}

// A jsonList is a JSON array column, as a nested list.
type jsonList struct {
	list    string
	key     []string
	elem    reflect.Type
	ordered bool
	mapKV   bool // a JSON object: entries name and value
}

var ifaceRef = `type union { type leafref { path "../../interface/name"; } type string; }`
var ifaceOrZone = `type union { type leafref { path "../../interface/name"; } type leafref { path "../../interface-zone/name"; } type string; }`
var addrRef = `type union { type leafref { path "../../../host/name"; } type leafref { path "../../../address-list/name"; } type string; }`
var svcRef = `type union { type leafref { path "../../../service/name"; } type string; }`
var vrfKey = idRef{leaf: "vrf", path: "../../vrf/name", null: "main"}

func routeMap(depth string) string {
	return `type leafref { path "` + depth + `route-map/name"; }`
}

func prefixList(depth string) string {
	return `type leafref { path "` + depth + `prefix-list/name"; }`
}

var peerRefs = map[string]string{
	"v4_prefix_list_in": prefixList("../../"), "v4_prefix_list_out": prefixList("../../"),
	"v6_prefix_list_in": prefixList("../../"), "v6_prefix_list_out": prefixList("../../"),
	"v4_route_map_in": routeMap("../../"), "v4_route_map_out": routeMap("../../"),
	"v6_route_map_in": routeMap("../../"), "v6_route_map_out": routeMap("../../"),
	"update_source": ifaceRef,
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

var tables = []table{
	{sql: "settings", list: "settings", module: "system", model: models.Settings{}, skip: []string{"last_commit", "web_certificate_id"},
		desc: "Settings of the firewalls, for every virtual firewall."},
	{sql: "instances", list: "instance", module: "system", key: []string{"name"}, model: models.Instance{},
		desc: "A virtual firewall: its own network namespace, routing table, firewall, DNS and DHCP server. The default one of a firewall is its host.",
		ids: map[string]idRef{
			"firewall_id":               {leaf: "firewall", external: "firewalls"},
			"acme_proxy_certificate_id": {leaf: "acme-proxy-certificate", path: "../certificate/name"},
		},
		json: map[string]jsonList{"ntp_servers": {list: "ntp-server", key: []string{"address"}, elem: reflect.TypeFor[fwconfig.NTPServer](), ordered: true}},
		refs: map[string]string{
			"dns_query_log_clients": `type union { type leafref { path "../../host/name"; } type leafref { path "../../address-list/name"; } type string; }`,
			"ntp_allow":             `type union { type leafref { path "../../host/name"; } type leafref { path "../../address-list/name"; } type string; }`,
			"snmp_allow":            `type union { type leafref { path "../../host/name"; } type leafref { path "../../address-list/name"; } type string; }`,
		},
		secret: []string{"snmp_community"}},
	{sql: "links", list: "link", module: "system", key: []string{"name"}, model: models.Link{},
		desc: "A point-to-point connection between two virtual firewalls of a firewall (a veth pair).",
		ids: map[string]idRef{
			"instance_a_id": {leaf: "instance-a", path: "../../instance/name"},
			"instance_b_id": {leaf: "instance-b", path: "../../instance/name"},
		}},

	{sql: "interfaces", list: "interface", module: "interfaces", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.Interface{},
		enums: map[string][]string{
			"kind":      {fwconfig.KindPhysical, fwconfig.KindVLAN, fwconfig.KindBridge, fwconfig.KindWireGuard, fwconfig.KindLoopback, fwconfig.Kind6in4, fwconfig.KindVXLAN, fwconfig.KindOpenVPN},
			"ipv4_mode": {fwconfig.ModeStatic, fwconfig.ModeDHCP, fwconfig.ModeNone},
		},
		refs: map[string]string{
			"parent":       `type leafref { path "../../interface/name"; }`,
			"members":      `type leafref { path "../../interface/name"; }`,
			"vxlan_device": `type leafref { path "../../interface/name"; }`,
			"vrf":          `type leafref { path "../../vrf/name"; }`,
		},
		ids: map[string]idRef{
			"ovpn_certificate_id": {leaf: "ovpn-certificate", path: "../../certificate/name"},
			"ovpn_role_id":        {leaf: "ovpn-role", external: "roles"},
		},
		secret: []string{"wg_private_key", "he_update_key", "ovpn_tls_crypt"}},
	{sql: "wg_peers", list: "wireguard-peer", module: "interfaces", parent: "interfaces", parCol: "interface_id", key: []string{"public_key"}, model: models.WgPeer{},
		secret: []string{"preshared_key", "client_private_key"}},
	{sql: "interface_zones", list: "interface-zone", module: "interfaces", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.InterfaceZone{},
		refs: map[string]string{"interfaces": ifaceRef}},
	{sql: "static_neighbours", list: "static-neighbour", module: "interfaces", parent: "instances", parCol: "instance_id", key: []string{"interface", "address"}, model: models.StaticNeighbour{},
		ids: map[string]idRef{"interface_id": {leaf: "interface", path: "../../interface/name"}}},

	{sql: "vrfs", list: "vrf", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.Vrf{},
		refs: map[string]string{"evpn_device": `type leafref { path "../../interface/name"; }`}},
	{sql: "routes", list: "route", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"id"}, model: models.Route{},
		ids: map[string]idRef{
			"interface_id": {leaf: "interface", path: "../../interface/name"},
			"vrf_id":       {leaf: "vrf", path: "../../vrf/name"},
		}},
	{sql: "policy_routes", list: "policy-route", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"id"}, ordered: "position", model: models.PolicyRoute{},
		refs: map[string]string{"in_interfaces": ifaceOrZone, "src_addrs": addrRef, "dst_addrs": addrRef, "services": svcRef},
		ids:  map[string]idRef{"interface_id": {leaf: "interface", path: "../../interface/name"}}},
	{sql: "route_prefix_lists", list: "prefix-list", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.RoutePrefixList{},
		json: map[string]jsonList{"entries": {list: "entry", key: []string{"seq"}, elem: reflect.TypeFor[fwconfig.PrefixListEntry]()}}},
	{sql: "route_as_path_lists", list: "as-path-list", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.RouteAsPathList{},
		json: map[string]jsonList{"entries": {list: "entry", key: []string{"action", "regex"}, elem: reflect.TypeFor[fwconfig.ASPathEntry](), ordered: true}}},
	{sql: "route_community_lists", list: "community-list", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.RouteCommunityList{},
		json: map[string]jsonList{"entries": {list: "entry", key: []string{"action", "value"}, elem: reflect.TypeFor[fwconfig.CommunityEntry](), ordered: true}}},
	{sql: "route_maps", list: "route-map", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.RouteMap{},
		json: map[string]jsonList{"entries": {list: "entry", key: []string{"seq"}, elem: reflect.TypeFor[fwconfig.RouteMapEntry]()}}},
	{sql: "bgp_configs", list: "bgp", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"vrf"}, model: models.BgpConfig{},
		ids: map[string]idRef{"vrf_id": vrfKey},
		refs: map[string]string{
			"redist_connected_v4_map": routeMap("../../"), "redist_static_v4_map": routeMap("../../"),
			"redist_connected_v6_map": routeMap("../../"), "redist_static_v6_map": routeMap("../../"),
			"redist_ospf_v4_map": routeMap("../../"), "redist_ospf_v6_map": routeMap("../../"),
			"redist_isis_v4_map": routeMap("../../"), "redist_isis_v6_map": routeMap("../../"),
		},
		json: map[string]jsonList{
			"networks":   {list: "network", key: []string{"prefix"}, elem: reflect.TypeFor[fwconfig.BGPNetwork]()},
			"aggregates": {list: "aggregate", key: []string{"prefix"}, elem: reflect.TypeFor[fwconfig.BGPAggregate]()},
		}},
	{sql: "bgp_peer_groups", list: "bgp-peer-group", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.BgpPeerGroup{},
		ids: map[string]idRef{"vrf_id": vrfKey}, refs: peerRefs, secret: []string{"password"}},
	{sql: "bgp_neighbors", list: "bgp-neighbor", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"vrf", "address"}, model: models.BgpNeighbor{},
		ids: map[string]idRef{"vrf_id": vrfKey}, secret: []string{"password"},
		refs: merge(peerRefs, map[string]string{
			"peer_group": `type leafref { path "../../bgp-peer-group/name"; }`,
			"interface":  ifaceRef,
		})},
	{sql: "ospf_configs", list: "ospf", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"version", "vrf"}, model: models.OspfConfig{},
		ids: map[string]idRef{"vrf_id": vrfKey},
		json: map[string]jsonList{
			"areas":        {list: "area", key: []string{"id"}, elem: reflect.TypeFor[fwconfig.OSPFArea]()},
			"ranges":       {list: "range", key: []string{"area", "prefix"}, elem: reflect.TypeFor[fwconfig.OSPFRange]()},
			"summaries":    {list: "summary", key: []string{"prefix"}, elem: reflect.TypeFor[fwconfig.OSPFSummary]()},
			"networks":     {list: "network", key: []string{"prefix"}, elem: reflect.TypeFor[fwconfig.OSPFNetwork]()},
			"redistribute": {list: "redistribute", key: []string{"source"}, elem: reflect.TypeFor[fwconfig.OSPFRedistribute]()},
		}},
	{sql: "ospf_interfaces", list: "ospf-interface", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"version", "name"}, model: models.OspfInterface{},
		refs: map[string]string{"name": ifaceRef}, secret: []string{"auth_key"}},
	{sql: "isis_configs", list: "isis", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"vrf"}, model: models.IsisConfig{},
		ids:  map[string]idRef{"vrf_id": vrfKey},
		refs: map[string]string{"net_interface": ifaceRef},
		json: map[string]jsonList{
			"default_originate": {list: "default-originate", key: []string{"family", "level"}, elem: reflect.TypeFor[fwconfig.ISISDefault]()},
			"redistribute":      {list: "redistribute", key: []string{"family", "source", "level"}, elem: reflect.TypeFor[fwconfig.ISISRedistribute]()},
		},
		secret: []string{"area_password", "domain_password"}},
	{sql: "isis_interfaces", list: "isis-interface", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.IsisInterface{},
		refs: map[string]string{"name": ifaceRef}, secret: []string{"password"}},
	{sql: "vrrp_routers", list: "vrrp-router", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"interface", "vrid"}, model: models.VrrpRouter{},
		refs: map[string]string{"interface": ifaceRef}},
	{sql: "bfd_interfaces", list: "bfd-interface", module: "routing", parent: "instances", parCol: "instance_id", key: []string{"interface"}, model: models.BfdInterface{},
		refs: map[string]string{"interface": ifaceRef}},

	{sql: "rules", list: "rule", module: "firewall", parent: "instances", parCol: "instance_id", key: []string{"id"}, ordered: "position", model: models.Rule{},
		desc: "A filter rule. The id is the rule's: accepted connections are marked with it, so a new rule takes an id never used before.",
		enums: map[string][]string{
			"chain":  {fwconfig.ChainInput, fwconfig.ChainForward, fwconfig.ChainOutput},
			"action": {fwconfig.ActionAccept, fwconfig.ActionDrop, fwconfig.ActionReject},
		},
		refs: map[string]string{
			"in_interfaces": ifaceOrZone, "out_interfaces": ifaceOrZone, "src_addrs": addrRef, "dst_addrs": addrRef, "services": svcRef,
			"rate_limit": `type leafref { path "../../rate-limit/name"; }`,
		}},
	{sql: "nat_rules", list: "nat-rule", module: "firewall", parent: "instances", parCol: "instance_id", key: []string{"id"}, ordered: "position", model: models.NatRule{},
		enums: map[string][]string{"kind": {fwconfig.NATMasquerade, fwconfig.NATSNAT, fwconfig.NATDNAT}},
		refs:  map[string]string{"in_interfaces": ifaceOrZone, "out_interfaces": ifaceOrZone, "src_addrs": addrRef, "dst_addrs": addrRef}},
	{sql: "rate_limits", list: "rate-limit", module: "firewall", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.RateLimit{}},

	{sql: "object_folders", list: "object-folder", module: "objects", key: []string{"id"}, model: models.ObjectFolder{},
		ids: map[string]idRef{"parent_id": {leaf: "parent", path: "../../object-folder/id"}}},
	{sql: "address_objects", list: "host", module: "objects", key: []string{"name"}, model: models.AddressObject{},
		ids: map[string]idRef{"folder_id": {leaf: "folder", path: "../../object-folder/id"}}},
	{sql: "address_lists", list: "address-list", module: "objects", key: []string{"name"}, model: models.AddressList{},
		ids:  map[string]idRef{"folder_id": {leaf: "folder", path: "../../object-folder/id"}},
		refs: map[string]string{"entries": `type union { type leafref { path "../../host/name"; } type leafref { path "../../address-list/name"; } type string; }`}},
	{sql: "ip_lists", list: "ip-list", module: "objects", key: []string{"name"}, model: models.IpList{},
		ids:    map[string]idRef{"folder_id": {leaf: "folder", path: "../../object-folder/id"}},
		secret: []string{"password", "api_key"}},
	{sql: "services", list: "service", module: "objects", key: []string{"name"}, model: models.Service{},
		json: map[string]jsonList{"ports": {list: "port", key: []string{"protocol", "dst_lo", "dst_hi", "src_lo", "src_hi"}, elem: reflect.TypeFor[models.ServicePort](), ordered: true}}},
	{sql: "port_names", list: "port-name", module: "objects", key: []string{"name"}, model: models.PortName{}},
	{sql: "tasks", list: "task", module: "objects", key: []string{"name"}, model: models.Task{},
		ids: map[string]idRef{
			"ip_list_id":  {leaf: "ip-list", path: "../../ip-list/name"},
			"firewall_id": {leaf: "firewall", external: "firewalls"},
		}},

	{sql: "ipam_prefixes", list: "ipam-prefix", module: "services", parent: "instances", parCol: "instance_id", key: []string{"prefix"}, model: models.IpamPrefix{}},
	{sql: "ipam_addresses", list: "ipam-address", module: "services", parent: "instances", parCol: "instance_id", key: []string{"address"}, model: models.IpamAddress{}},
	{sql: "dns_soa_templates", list: "dns-soa-template", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.DnsSoaTemplate{}},
	{sql: "dns_dnssec_policies", list: "dnssec-policy", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.DnsDnssecPolicy{}},
	{sql: "dns_templates", list: "dns-template", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.DnsTemplate{},
		ids: map[string]idRef{
			"soa_template_id":  {leaf: "soa-template", global: "../../dns-soa-template/name"},
			"dnssec_policy_id": {leaf: "dnssec-policy", global: "../../dnssec-policy/name"},
		},
		json: map[string]jsonList{"nameservers": {list: "nameserver", key: []string{"name", "address"}, elem: reflect.TypeFor[models.DnsNameserver](), ordered: true}}},
	{sql: "dns_zones", list: "dns-zone", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.DnsZone{},
		ids: map[string]idRef{"dns_template_id": {leaf: "dns-template", global: "../../dns-template/name"}}},
	{sql: "dns_records", list: "record", module: "services", parent: "dns_zones", parCol: "zone_id", key: []string{"id"}, ordered: "rank", model: models.DnsRecord{}},
	{sql: "dns_blocklists", list: "dns-blocklist", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.DnsBlocklist{},
		secret: []string{"auth_key"}},
	{sql: "dyndns_clients", list: "dns-update", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.DyndnsClient{},
		ids:    map[string]idRef{"interface_id": {leaf: "interface", path: "../../interface/name"}},
		json:   map[string]jsonList{"provider_settings": {list: "provider-setting", key: []string{"name"}, mapKV: true}},
		secret: []string{"tsig_secret"}},
	{sql: "dyndns_records", list: "record", module: "services", parent: "dyndns_clients", parCol: "client_id", key: []string{"id"}, model: models.DyndnsRecord{}},
	{sql: "certificates", list: "certificate", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.Certificate{},
		ids: map[string]idRef{
			"interface_id":     {leaf: "interface", path: "../../interface/name"},
			"dyndns_client_id": {leaf: "dns-update", path: "../../dns-update/name"},
		},
		secret: []string{"priv_key"}},
	{sql: "acme_proxy_policies", list: "acme-proxy-policy", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.AcmeProxyPolicy{},
		ids: map[string]idRef{
			"interface_id":     {leaf: "interface", path: "../../interface/name"},
			"dyndns_client_id": {leaf: "dns-update", path: "../../dns-update/name"},
		}},
	{sql: "snmp_users", list: "snmp-user", module: "services", parent: "instances", parCol: "instance_id", key: []string{"name"}, model: models.SnmpUser{},
		secret: []string{"auth_password", "priv_password"}},
	{sql: "syslog_servers", list: "syslog-server", module: "services", parent: "instances", parCol: "instance_id", key: []string{"id"}, model: models.SyslogServer{}},
}

type column struct {
	name    string
	typ     string
	notnull bool
	dflt    *string
}

var comments = map[string]map[string]string{} // Go type → field → comment

func main() {
	out := flag.String("out", "yang", "directory to write the modules to")
	flag.Parse()
	for _, dir := range []string{"models", "internal/fwconfig"} {
		readComments(dir)
	}
	tmp, err := os.MkdirTemp("", "yanggen")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)
	db, err := dbmigrate.Open(filepath.Join(tmp, "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		log.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		log.Fatal(err)
	}
	byModule := map[string]*strings.Builder{}
	byTable := map[string]*table{}
	for i := range tables {
		byTable[tables[i].sql] = &tables[i]
	}
	children := map[string][]*table{}
	for i := range tables {
		t := &tables[i]
		if t.parent != "" && t.parent != "instances" {
			children[t.parent] = append(children[t.parent], t)
		}
	}
	for i := range tables {
		t := &tables[i]
		if t.parent != "" && t.parent != "instances" {
			continue // written inside its parent
		}
		b := byModule[t.module]
		if b == nil {
			b = &strings.Builder{}
			byModule[t.module] = b
		}
		writeTable(b, db, t, children, "    ")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	mods := []string{}
	for m := range byModule {
		mods = append(mods, m)
	}
	sort.Strings(mods)
	for _, m := range mods {
		if err := os.WriteFile(filepath.Join(*out, "portitor-"+m+".yang"), []byte(submodule(m, byModule[m].String())), 0o644); err != nil {
			log.Fatal(err)
		}
	}
}

func submodule(name, body string) string {
	inc := ""
	if name == "system" {
		// The instance list uses the per-instance groupings.
		inc = "  include portitor-interfaces;\n  include portitor-routing;\n  include portitor-firewall;\n  include portitor-services;\n  include portitor-state;\n"
	}
	return fmt.Sprintf(`// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

submodule portitor-%s {
  yang-version 1.1;
  belongs-to portitor { prefix pt; }
  import portitor-extensions { prefix px; }
%s
  description "Portitor configuration: %s.";

  revision 2026-11-08 { description "First version, from the SQLite schema."; }

  grouping %s {
%s  }
}
`, name, inc, name, name, body)
}

func columns(db *gorm.DB, tbl string) []column {
	var cols []struct {
		Name    string
		Type    string
		Notnull int
		Dflt    *string `gorm:"column:dflt_value"`
	}
	if err := db.Raw(`select name, type, "notnull", dflt_value from pragma_table_info(?)`, tbl).Scan(&cols).Error; err != nil {
		log.Fatal(err)
	}
	out := make([]column, len(cols))
	for i, c := range cols {
		out[i] = column{c.Name, c.Type, c.Notnull == 1, c.Dflt}
	}
	return out
}

var cache = &sync.Map{}

// fields maps a model's columns to its fields.
func fields(model any) map[string]*schema.Field {
	s, err := schema.Parse(model, cache, schema.NamingStrategy{})
	if err != nil {
		log.Fatal(err)
	}
	out := map[string]*schema.Field{}
	for _, f := range s.Fields {
		if f.DBName != "" {
			out[f.DBName] = f
		}
	}
	return out
}

func writeTable(b *strings.Builder, db *gorm.DB, t *table, children map[string][]*table, ind string) {
	fs := fields(t.model)
	mt := reflect.TypeOf(t.model)
	if t.sql == "settings" {
		fmt.Fprintf(b, "%scontainer %s {\n", ind, t.list)
		fmt.Fprintf(b, "%s  px:table %q;\n%s  px:singleton 1;\n", ind, t.sql, ind)
	} else {
		fmt.Fprintf(b, "%slist %s {\n", ind, t.list)
		fmt.Fprintf(b, "%s  key %q;\n", ind, strings.Join(leafNames(t, t.key), " "))
		if t.ordered != "" {
			fmt.Fprintf(b, "%s  ordered-by user;\n%s  px:position %q;\n", ind, ind, t.ordered)
		}
		fmt.Fprintf(b, "%s  px:table %q;\n", ind, t.sql)
		if t.parCol != "" {
			fmt.Fprintf(b, "%s  px:parent-column %q;\n", ind, t.parCol)
		}
	}
	if t.desc != "" {
		fmt.Fprintf(b, "%s  description %s;\n", ind, quote(t.desc))
	} else if c := typeComment(mt); c != "" {
		fmt.Fprintf(b, "%s  description %s;\n", ind, quote(c))
	}
	cols := columns(db, t.sql)
	// Keys first, in key order.
	sort.SliceStable(cols, func(i, j int) bool { return keyIndex(t, cols[i].name) < keyIndex(t, cols[j].name) })
	for _, c := range cols {
		if skipColumn(t, c.name) {
			continue
		}
		f := fs[c.name]
		if f == nil {
			log.Fatalf("%s.%s: no model field", t.sql, c.name)
		}
		writeColumn(b, t, c, f, mt, ind+"  ")
	}
	for _, ch := range children[t.sql] {
		writeTable(b, db, ch, children, ind+"  ")
	}
	if t.sql == "instances" {
		for _, g := range []string{"interfaces", "routing", "firewall", "services", "instance-state"} {
			fmt.Fprintf(b, "%s  uses %s;\n", ind, g)
		}
	}
	fmt.Fprintf(b, "%s}\n", ind)
}

func keyIndex(t *table, col string) int {
	for i, k := range t.key {
		if k == col || (t.ids[col].leaf == k) {
			return i
		}
	}
	return len(t.key)
}

func leafNames(t *table, cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = strings.ReplaceAll(c, "_", "-")
	}
	return out
}

func skipColumn(t *table, c string) bool {
	switch c {
	case "created_at", "updated_at":
		return true
	case "id":
		return !(len(t.key) > 0 && contains(t.key, "id"))
	}
	if c == t.parCol || c == t.ordered || contains(t.skip, c) {
		return true
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func writeColumn(b *strings.Builder, t *table, c column, f *schema.Field, mt reflect.Type, ind string) {
	if j, ok := t.json[c.name]; ok {
		writeJSONList(b, c.name, j, comment(f), ind)
		return
	}
	name := strings.ReplaceAll(c.name, "_", "-")
	id, isID := t.ids[c.name]
	if isID {
		name = id.leaf
	}
	isKey := contains(t.key, c.name) || (isID && contains(t.key, id.leaf))
	list := c.typ == "TEXT" && c.dflt != nil && *c.dflt == "'[]'"
	kw := "leaf"
	if list {
		kw = "leaf-list"
	}
	fmt.Fprintf(b, "%s%s %s {\n", ind, kw, name)
	switch {
	case isID && id.external != "":
		fmt.Fprintf(b, "%s  type string;\n%s  px:external %q;\n", ind, ind, id.external)
	case isID && id.global != "":
		fmt.Fprintf(b, "%s  type string;\n%s  px:global-ref %q;\n", ind, ind, id.global)
	case isID && id.null != "":
		fmt.Fprintf(b, "%s  type union { type enumeration { enum %s; } type leafref { path %q; } }\n%s  px:null-value %q;\n", ind, id.null, id.path, ind, id.null)
	case isID:
		fmt.Fprintf(b, "%s  type leafref { path %q; }\n", ind, id.path)
	case c.name == "id":
		fmt.Fprintf(b, "%s  type uint32;\n", ind)
	case t.refs[c.name] != "":
		fmt.Fprintf(b, "%s  %s\n", ind, t.refs[c.name])
	case t.enums[c.name] != nil:
		fmt.Fprintf(b, "%s  type enumeration {", ind)
		for _, e := range t.enums[c.name] {
			fmt.Fprintf(b, " enum %q;", e)
		}
		fmt.Fprintf(b, " }\n")
	default:
		fmt.Fprintf(b, "%s  type %s;\n", ind, yangType(c, f.FieldType))
	}
	if isID {
		fmt.Fprintf(b, "%s  px:column %q;\n", ind, c.name)
	}
	if list {
		fmt.Fprintf(b, "%s  ordered-by user;\n", ind)
	}
	if !isKey && !list && !isID {
		if d := yangDefault(c); d != "" {
			fmt.Fprintf(b, "%s  default %s;\n", ind, d)
		} else if c.notnull && c.dflt == nil {
			fmt.Fprintf(b, "%s  mandatory true;\n", ind)
		}
		if !c.notnull {
			fmt.Fprintf(b, "%s  px:nullable;\n", ind)
		}
	}
	if contains(t.secret, c.name) {
		fmt.Fprintf(b, "%s  px:secret;\n", ind)
	}
	if d := comment(f); d != "" {
		fmt.Fprintf(b, "%s  description %s;\n", ind, quote(d))
	}
	fmt.Fprintf(b, "%s}\n", ind)
}

func writeJSONList(b *strings.Builder, col string, j jsonList, desc, ind string) {
	fmt.Fprintf(b, "%slist %s {\n", ind, j.list)
	fmt.Fprintf(b, "%s  key %q;\n", ind, strings.Join(leafNames(nil, j.key), " "))
	if j.ordered {
		fmt.Fprintf(b, "%s  ordered-by user;\n", ind)
	}
	if j.mapKV {
		fmt.Fprintf(b, "%s  px:json-map %q;\n", ind, col)
	} else {
		fmt.Fprintf(b, "%s  px:json %q;\n", ind, col)
	}
	if desc != "" {
		fmt.Fprintf(b, "%s  description %s;\n", ind, quote(desc))
	}
	if j.mapKV {
		fmt.Fprintf(b, "%s  leaf name { type string; }\n%s  leaf value { type string; px:secret; }\n%s}\n", ind, ind, ind)
		return
	}
	for i := 0; i < j.elem.NumField(); i++ {
		sf := j.elem.Field(i)
		tag := strings.Split(sf.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.ReplaceAll(tag, "_", "-")
		ft := sf.Type
		ptr := ft.Kind() == reflect.Pointer
		if ptr {
			ft = ft.Elem()
		}
		fmt.Fprintf(b, "%s  leaf %s {\n%s    type %s;\n", ind, name, ind, goYang(ft))
		if !contains(j.key, tag) && !ptr && ft.Kind() != reflect.String && ft.Kind() != reflect.Bool {
			fmt.Fprintf(b, "%s    default 0;\n", ind)
		}
		if ptr {
			fmt.Fprintf(b, "%s    px:nullable;\n", ind)
		}
		if d := comments[typeKey(j.elem)][sf.Name]; d != "" {
			fmt.Fprintf(b, "%s    description %s;\n", ind, quote(d))
		}
		fmt.Fprintf(b, "%s  }\n", ind)
	}
	fmt.Fprintf(b, "%s}\n", ind)
}

func goYang(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int32:
		return "int32"
	case reflect.Int64:
		return "int64"
	case reflect.Uint32, reflect.Uint:
		return "uint32"
	}
	return "string"
}

func yangType(c column, ft reflect.Type) string {
	switch c.typ {
	case "BOOLEAN":
		return "boolean"
	case "INTEGER":
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		return goYang(ft)
	}
	return "string"
}

func yangDefault(c column) string {
	if c.dflt == nil {
		return ""
	}
	d := *c.dflt
	switch {
	case d == "''" || d == "0" || d == "false" || d == "'[]'" || d == "'{}'":
		return ""
	case strings.HasPrefix(d, "'"):
		return quote(strings.Trim(d, "'"))
	}
	return d
}

func quote(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func comment(f *schema.Field) string {
	return commentIn(f.Schema.ModelType, f.Name)
}

// commentIn is the comment of a field of t, or of a struct t embeds.
func commentIn(t reflect.Type, field string) string {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if c, ok := comments[typeKey(t)][field]; ok {
		return c
	}
	for i := 0; i < t.NumField(); i++ {
		if sf := t.Field(i); sf.Anonymous && sf.Type.Kind() == reflect.Struct {
			if c := commentIn(sf.Type, field); c != "" {
				return c
			}
		}
	}
	return ""
}

// typeKey names a type as comments does: package and name.
func typeKey(t reflect.Type) string {
	return filepath.Base(t.PkgPath()) + "." + t.Name()
}

func typeComment(t reflect.Type) string {
	return comments[typeKey(t)][""]
}

// readComments reads the doc comments of struct types and their fields.
func readComments(dir string) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, s := range g.Specs {
					ts, ok := s.(*ast.TypeSpec)
					if !ok {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					m := map[string]string{}
					if g.Doc != nil {
						m[""] = g.Doc.Text()
					}
					var last string
					for _, fl := range st.Fields.List {
						text := ""
						if fl.Doc != nil {
							text = fl.Doc.Text()
							last = text
						} else if fl.Comment != nil {
							text = fl.Comment.Text()
						}
						for _, n := range fl.Names {
							if text != "" {
								m[n.Name] = text
							} else if fl.Doc == nil && last != "" && len(fl.Names) > 0 {
								// A field in a group under one comment.
								m[n.Name] = ""
							}
						}
						if fl.Doc == nil && fl.Comment == nil {
							last = ""
						}
					}
					comments[filepath.Base(dir)+"."+ts.Name.Name] = m
				}
			}
		}
	}
}
