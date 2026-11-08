// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlmap

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/dbmigrate"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := dbmigrate.Open(filepath.Join(t.TempDir(), "db.sqlite"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbmigrate.Up(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func mustCreate(t *testing.T, db *gorm.DB, v any) {
	t.Helper()
	if err := db.Create(v).Error; err != nil {
		t.Fatal(err)
	}
}

func ptr(v uint) *uint { return &v }

// seed makes a configuration that uses every kind of mapping: id
// references, global DNS templates, JSON columns, ordered lists, nested
// tables and external names.
func seed(t *testing.T, db *gorm.DB) {
	t.Helper()
	fw := models.Firewall{Name: "fw1"}
	mustCreate(t, db, &fw)
	host := models.Instance{Name: "host", IsDefault: true, FirewallID: fw.ID, DnsUpstream: "forward", DnsForwardMode: "first",
		NtpServers: models.JSONList[fwconfig.NTPServer]{{Address: "pool.ntp.org", Pool: true}}}
	mustCreate(t, db, &host)
	vf := models.Instance{Name: "blue", FirewallID: fw.ID, DnsUpstream: "forward", DnsForwardMode: "first"}
	mustCreate(t, db, &vf)
	wan := models.Interface{InstanceID: host.ID, Name: "wan0", Kind: "physical", Enabled: true, Ipv4Mode: "dhcp", HaMonitor: true, DelegatedSlaac: true, WgKeepalive: 25, OvpnMode: "adaptive", OvpnPort: 1194}
	mustCreate(t, db, &wan)
	lan := models.Interface{InstanceID: host.ID, Name: "lan0", Kind: "physical", Enabled: true, Ipv4Mode: "static", Addresses: models.StringList{"192.168.1.1/24"}, Mtu: 1500, HaMonitor: true, DelegatedSlaac: true, WgKeepalive: 25, OvpnMode: "adaptive", OvpnPort: 1194}
	mustCreate(t, db, &lan)
	priv, pub, _ := wgkeys.Generate()
	_, peerPub, _ := wgkeys.Generate()
	wgKey = priv
	wg := models.Interface{InstanceID: host.ID, Name: "wg0", Kind: "wireguard", Enabled: true, Ipv4Mode: "static", WgPrivateKey: priv, WgPublicKey: pub, Addresses: models.StringList{"10.9.0.1/24"}, HaMonitor: true, DelegatedSlaac: true, WgKeepalive: 25, OvpnMode: "adaptive", OvpnPort: 1194}
	mustCreate(t, db, &wg)
	mustCreate(t, db, &models.WgPeer{InterfaceID: wg.ID, Name: "phone", Enabled: true, PublicKey: peerPub, AllowedIPs: models.StringList{"10.9.0.2/32"}})
	vrf := models.Vrf{InstanceID: host.ID, Name: "red", RouteTable: 100, EvpnAdvertiseV4: true, EvpnAdvertiseV6: true}
	mustCreate(t, db, &vrf)
	mustCreate(t, db, &models.Route{InstanceID: host.ID, Destination: "10.0.0.0/8", Gateway: "192.168.1.254", InterfaceID: &lan.ID, VrfID: &vrf.ID, Enabled: true})
	mustCreate(t, db, &models.StaticNeighbour{InstanceID: host.ID, InterfaceID: lan.ID, Address: "192.168.1.9", MAC: "02:00:00:00:00:09", Enabled: true})
	mustCreate(t, db, &models.InterfaceZone{InstanceID: host.ID, Name: "inside", Interfaces: models.StringList{"lan0", "wg0"}})
	mustCreate(t, db, &models.BgpConfig{InstanceID: host.ID, Enabled: true, Asn: 65000, LogNeighborChanges: true,
		Networks: models.JSONList[fwconfig.BGPNetwork]{{Prefix: "192.168.1.0/24"}}})
	mustCreate(t, db, &models.BgpConfig{InstanceID: host.ID, VrfID: &vrf.ID, Asn: 65000, LogNeighborChanges: true})
	mustCreate(t, db, &models.BgpNeighbor{InstanceID: host.ID, Address: "192.0.2.1", Enabled: true, BgpPeerSettings: models.BgpPeerSettings{RemoteAs: "65001", Password: "pw"}})
	mustCreate(t, db, &models.RoutePrefixList{InstanceID: host.ID, Name: "lan", Family: "ipv4",
		Entries: models.JSONList[fwconfig.PrefixListEntry]{{Seq: 10, Action: "permit", Prefix: "192.168.0.0/16", LE: 24}}})
	soa := models.DnsSoaTemplate{InstanceID: host.ID, Global: true, Name: "std", Mname: "ns1.example.com.", Rname: "hostmaster.example.com.", Refresh: 86400, Retry: 7200, Expire: 3600000, Minimum: 3600}
	mustCreate(t, db, &soa)
	tmpl := models.DnsTemplate{InstanceID: host.ID, Global: true, Name: "std", SoaTemplateID: soa.ID, DefaultTtl: 3600,
		Nameservers: models.DnsNameserverList{{Name: "ns1.example.com."}}}
	mustCreate(t, db, &tmpl)
	zone := models.DnsZone{InstanceID: vf.ID, Name: "blue.example.com", Type: "forward", DnsTemplateID: &tmpl.ID}
	mustCreate(t, db, &zone)
	mustCreate(t, db, &models.DnsRecord{ZoneID: zone.ID, Rank: 0, Name: "www", Type: "A", Value: "192.168.2.10"})
	mustCreate(t, db, &models.DnsRecord{ZoneID: zone.ID, Rank: 1, Name: "mail", Type: "A", Value: "192.168.2.11"})
	dd := models.DyndnsClient{InstanceID: host.ID, Name: "home", Enabled: true, InterfaceID: wan.ID, Server: "", Zone: "example.com", Provider: "cloudflare",
		ProviderSettings: models.StringMap{"api_token": "tok"}}
	mustCreate(t, db, &dd)
	mustCreate(t, db, &models.DyndnsRecord{ClientID: dd.ID, Name: "home", Type: "A"})
	mustCreate(t, db, &models.Certificate{InstanceID: host.ID, Name: "gui", Enabled: true, Source: "acme", Domains: models.StringList{"fw.example.com"},
		Ca: "letsencrypt", KeyType: "ec256", Challenge: "dns-01", DyndnsClientID: &dd.ID})
	folder := models.ObjectFolder{Kind: "hosts", Name: "servers"}
	mustCreate(t, db, &folder)
	mustCreate(t, db, &models.AddressObject{Name: "web", Addresses: models.StringList{"192.168.1.10"}, FolderID: &folder.ID})
	mustCreate(t, db, &models.AddressList{Name: "dmz", Entries: models.StringList{"web", "192.168.3.0/24"}})
	mustCreate(t, db, &models.Service{Name: "app", Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 8080}}})
	ipl := models.IpList{Name: "bad", Source: fwconfig.IPListURL, Url: "https://example.com/bad.txt"}
	mustCreate(t, db, &ipl)
	mustCreate(t, db, &models.Task{Name: "bad refresh", Enabled: true, Schedule: "0 * * * *", Kind: fwconfig.TaskIPList, IpListID: &ipl.ID, FirewallID: fw.ID})
	for i, chain := range []string{"input", "forward", "input"} {
		mustCreate(t, db, &models.Rule{InstanceID: host.ID, Position: i * 10, Chain: chain, Action: "accept", Enabled: true,
			InInterfaces: models.StringList{"inside"}, SrcAddrs: models.StringList{"dmz"}, Services: models.StringList{"app"}, SynProxyWScale: 7})
	}
	mustCreate(t, db, &models.NatRule{InstanceID: host.ID, Kind: "masquerade", OutInterfaces: models.StringList{"wan0"}, Enabled: true})
	mustCreate(t, db, &models.Link{Name: "l1", InstanceAID: host.ID, InterfaceA: "to-blue", AddressesA: models.StringList{"10.255.0.1/30"},
		InstanceBID: vf.ID, InterfaceB: "to-host", AddressesB: models.StringList{"10.255.0.2/30"}})
}

// wgKey is wg0's private key, a secret that must come through a write.
var wgKey string

func mapping(t *testing.T) *Mapping {
	t.Helper()
	m, err := New(schema.MustLoad())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestImport(t *testing.T) {
	db := testDB(t)
	seed(t, db)
	m := mapping(t)
	tree, idx, err := m.Import(db)
	if err != nil {
		t.Fatal(err)
	}
	if errs := tree.Validate(); len(errs) != 0 {
		t.Errorf("imported tree: %v", errs)
	}
	host := tree.Root.Entry("instance", []string{"host"})
	if host == nil || host.Leaves["firewall"] != "fw1" {
		t.Fatalf("host: %+v", host)
	}
	route := host.Lists["route"][0]
	if route.Leaves["interface"] != "lan0" || route.Leaves["vrf"] != "red" {
		t.Errorf("route: %v", route.Leaves)
	}
	if host.Entry("bgp", []string{"main"}) == nil || host.Entry("bgp", []string{"red"}) == nil {
		t.Errorf("bgp entries: %v", host.Lists["bgp"])
	}
	if host.Entry("static-neighbour", []string{"lan0", "192.168.1.9"}) == nil {
		t.Error("static neighbour keyed by interface name")
	}
	zone := tree.Root.Entry("instance", []string{"blue"}).Entry("dns-zone", []string{"blue.example.com"})
	if zone.Leaves["dns-template"] != "std" || len(zone.Lists["record"]) != 2 || zone.Lists["record"][0].Leaves["name"] != "www" {
		t.Errorf("zone: %v %v", zone.Leaves, zone.Lists["record"])
	}
	pl := host.Entry("prefix-list", []string{"lan"}).Entry("entry", []string{"10"})
	if pl == nil || pl.Leaves["le"] != "24" || pl.Leaves["prefix"] != "192.168.0.0/16" {
		t.Errorf("prefix list entry: %+v", pl)
	}
	if got := host.Lists["rule"]; len(got) != 3 || idx[got[0]] >= idx[got[2]] {
		t.Errorf("rules: %v", got)
	}
	if host.Entry("interface", []string{"lan0"}).Leaves["enabled"] != "" {
		t.Error("a leaf at its default is set")
	}
	if tree.Root.Containers["settings"] == nil {
		t.Error("no settings")
	}
}

// docs builds each firewall's document, for comparing the database before
// and after a round trip.
func docs(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var fw models.Firewall
	if err := db.Where("name = ?", "fw1").First(&fw).Error; err != nil {
		t.Fatal(err)
	}
	doc, err := builder.BuildFirewall(db, 1, fw.ID)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func TestWriteUnchanged(t *testing.T) {
	db := testDB(t)
	seed(t, db)
	m := mapping(t)
	before := docs(t, db)
	tree, _, err := m.Import(db)
	if err != nil {
		t.Fatal(err)
	}
	var stamps []string
	db.Raw("SELECT name || updated_at FROM interfaces ORDER BY id").Scan(&stamps)
	if err := db.Transaction(func(tx *gorm.DB) error { return m.Write(tx, tree) }); err != nil {
		t.Fatal(err)
	}
	var after []string
	db.Raw("SELECT name || updated_at FROM interfaces ORDER BY id").Scan(&after)
	if !slices.Equal(stamps, after) {
		t.Errorf("unchanged rows were updated: %v → %v", stamps, after)
	}
	if got := docs(t, db); got != before {
		t.Errorf("document changed:\n%s\n%s", before, got)
	}
}

func TestWriteChanges(t *testing.T) {
	db := testDB(t)
	seed(t, db)
	m := mapping(t)
	tree, idx, err := m.Import(db)
	if err != nil {
		t.Fatal(err)
	}
	host := datastore.Path{{Name: "instance", Keys: []string{"host"}}}
	at := func(more ...datastore.Elem) datastore.Path { return append(append(datastore.Path{}, host...), more...) }
	ruleIDs := []int64{}
	for _, r := range tree.Root.Entry("instance", []string{"host"}).Lists["rule"] {
		ruleIDs = append(ruleIDs, idx[r])
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// A new VRF and a route in it, a renamed interface, a moved rule, a
	// deleted zone and a changed JSON entry.
	must(tree.Set(at(datastore.Elem{Name: "vrf", Keys: []string{"green"}}, datastore.Elem{Name: "route-table"}), "200"))
	must(tree.Set(at(datastore.Elem{Name: "route", Keys: []string{"50"}}, datastore.Elem{Name: "destination"}), "10.20.0.0/16"))
	must(tree.Set(at(datastore.Elem{Name: "route", Keys: []string{"50"}}, datastore.Elem{Name: "vrf"}), "green"))
	must(tree.Set(at(datastore.Elem{Name: "route", Keys: []string{"50"}}, datastore.Elem{Name: "gateway"}), "192.168.1.253"))
	must(tree.Rename(at(datastore.Elem{Name: "interface", Keys: []string{"lan0"}}), []string{"lan1"}))
	must(tree.Move(at(datastore.Elem{Name: "rule", Keys: []string{itoa(ruleIDs[2])}}), "first", nil))
	must(tree.Delete(at(datastore.Elem{Name: "interface-zone", Keys: []string{"inside"}})))
	must(tree.Set(at(datastore.Elem{Name: "prefix-list", Keys: []string{"lan"}}, datastore.Elem{Name: "entry", Keys: []string{"10"}}, datastore.Elem{Name: "le"}), "28"))
	// The rules named the zone: give them interfaces instead.
	for _, r := range tree.Root.Entry("instance", []string{"host"}).Lists["rule"] {
		r.LeafLists["in-interfaces"] = []string{"lan1"}
	}
	if err := db.Transaction(func(tx *gorm.DB) error { return m.Write(tx, tree) }); err != nil {
		t.Fatal(err)
	}
	back, idx2, err := m.Import(db)
	if err != nil {
		t.Fatal(err)
	}
	if d := datastore.Diff(tree, back); len(d) != 0 {
		t.Errorf("read back differs: %+v", d)
	}
	var route models.Route
	db.Where("destination = ?", "10.20.0.0/16").First(&route)
	var green models.Vrf
	db.Where("name = ?", "green").First(&green)
	if route.ID != 50 || route.VrfID == nil || *route.VrfID != green.ID {
		t.Errorf("route %+v, vrf green %d", route, green.ID)
	}
	// The rules keep their ids, in their new order.
	got := []int64{}
	for _, r := range back.Root.Entry("instance", []string{"host"}).Lists["rule"] {
		got = append(got, idx2[r])
	}
	if want := []int64{ruleIDs[2], ruleIDs[0], ruleIDs[1]}; !slices.Equal(got, want) {
		t.Errorf("rule ids %v, want %v", got, want)
	}
	var n int64
	db.Model(&models.InterfaceZone{}).Count(&n)
	if n != 0 {
		t.Errorf("%d zones left", n)
	}
	// The secrets came through: the WireGuard key and the BGP password.
	var wg models.Interface
	db.Where("name = ?", "wg0").First(&wg)
	var nb models.BgpNeighbor
	db.First(&nb)
	if wg.WgPrivateKey != wgKey || nb.Password != "pw" {
		t.Errorf("secrets lost: %q %q", wg.WgPrivateKey, nb.Password)
	}
	docs(t, db)
}

func itoa(n int64) string { return json.Number(jsonInt(n)).String() }

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// notConfiguration are the tables that are not in the tree: users and
// their roles, the firewalls (the hosts and their agents), the directory,
// and what portitor-config records.
var notConfiguration = []string{"users", "roles", "role_members", "role_instances", "firewalls", "ldap_servers",
	"ldap_role_mappings", "deployments", "known_interfaces", "goose_db_version"}

// notMapped are columns of mapped tables that are not leaves.
var notMapped = map[string][]string{"settings": {"last_commit", "web_certificate_id"}}

// TestEveryColumnMapped keeps the YANG modules and the tables in step: a
// new table or column needs its list or leaf (or a place above).
func TestEveryColumnMapped(t *testing.T) {
	db := testDB(t)
	m := mapping(t)
	mapped := map[string]*table{}
	for _, tb := range m.tables {
		mapped[tb.name] = tb
	}
	var tables []string
	db.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&tables)
	for _, name := range tables {
		tb := mapped[name]
		if tb == nil {
			if !slices.Contains(notConfiguration, name) {
				t.Errorf("table %s has no list in the YANG modules (px:table) and is not in notConfiguration", name)
			}
			continue
		}
		have := []string{"id", "created_at", "updated_at", tb.parentCol, tb.position}
		have = append(have, notMapped[name]...)
		for _, c := range tb.cols {
			have = append(have, c.column)
		}
		for _, j := range tb.jsons {
			have = append(have, j.column)
		}
		var cols []string
		db.Raw("SELECT name FROM pragma_table_info(?)", name).Scan(&cols)
		for _, c := range cols {
			if !slices.Contains(have, c) {
				t.Errorf("column %s.%s has no leaf in the YANG modules", name, c)
			}
		}
	}
}
