// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package confview

import (
	"reflect"
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/datastore/sqlmap"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/records"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

// testDB is a test's records (the ids are kept in them).
type testDB struct{ rec *records.Files }

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	return &testDB{rec: records.NewFiles("")}
}

func testMapping(t *testing.T) *sqlmap.Mapping {
	t.Helper()
	m, err := Mapping()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// adder adds models to a tree as an import does (sqlmap.Adder), giving
// each a made-up id for those after it to name.
type adder struct {
	a    *sqlmap.Adder
	next uint
}

func newAdder(t *testing.T, db *testDB, tree *datastore.Tree) *adder {
	return &adder{a: testMapping(t).NewAdder(tree, sqlmap.Index{}), next: 1000}
}

func (a *adder) create(t *testing.T, model any) {
	t.Helper()
	tbl, row, err := RowOf(model)
	if err != nil {
		t.Fatal(err)
	}
	if row["id"] == int64(0) {
		a.next++
		row["id"] = int64(a.next)
		model.(interface{ SetID(uint) }).SetID(a.next)
	}
	if _, err := a.a.Add(tbl, row); err != nil {
		t.Fatalf("%s: %v", tbl, err)
	}
}

func ptr(v uint) *uint { return &v }

// seed makes a configuration that uses every kind of mapping: id
// references, global DNS templates, JSON columns, ordered lists, nested
// tables and external names.
func seed(t *testing.T, db *testDB, add *adder) {
	t.Helper()
	fw := models.Firewall{Name: "fw1"}
	add.create(t, &fw)
	host := models.Instance{Name: "host", IsDefault: true, FirewallID: fw.ID, DnsUpstream: "forward", DnsForwardMode: "first",
		NtpServers: models.JSONList[fwconfig.NTPServer]{{Address: "pool.ntp.org", Pool: true}}}
	add.create(t, &host)
	vf := models.Instance{Name: "blue", FirewallID: fw.ID, DnsUpstream: "forward", DnsForwardMode: "first"}
	add.create(t, &vf)
	wan := models.Interface{InstanceID: host.ID, Name: "wan0", Kind: "physical", Enabled: true, Ipv4Mode: "dhcp", HaMonitor: true, DelegatedSlaac: true, WgKeepalive: 25, OvpnMode: "adaptive", OvpnPort: 1194}
	add.create(t, &wan)
	lan := models.Interface{InstanceID: host.ID, Name: "lan0", Kind: "physical", Enabled: true, Ipv4Mode: "static", Addresses: models.StringList{"192.168.1.1/24"}, Mtu: 1500, HaMonitor: true, DelegatedSlaac: true, WgKeepalive: 25, OvpnMode: "adaptive", OvpnPort: 1194}
	add.create(t, &lan)
	priv, pub, _ := wgkeys.Generate()
	_, peerPub, _ := wgkeys.Generate()
	wgKey = priv
	wg := models.Interface{InstanceID: host.ID, Name: "wg0", Kind: "wireguard", Enabled: true, Ipv4Mode: "static", WgPrivateKey: priv, WgPublicKey: pub, Addresses: models.StringList{"10.9.0.1/24"}, HaMonitor: true, DelegatedSlaac: true, WgKeepalive: 25, OvpnMode: "adaptive", OvpnPort: 1194}
	add.create(t, &wg)
	add.create(t, &models.WgPeer{InterfaceID: wg.ID, Name: "phone", Enabled: true, PublicKey: peerPub, AllowedIPs: models.StringList{"10.9.0.2/32"}})
	vrf := models.Vrf{InstanceID: host.ID, Name: "red", RouteTable: 100, EvpnAdvertiseV4: true, EvpnAdvertiseV6: true}
	add.create(t, &vrf)
	add.create(t, &models.Route{InstanceID: host.ID, Destination: "10.0.0.0/8", Gateway: "192.168.1.254", InterfaceID: &lan.ID, VrfID: &vrf.ID, Enabled: true})
	add.create(t, &models.StaticNeighbour{InstanceID: host.ID, InterfaceID: lan.ID, Address: "192.168.1.9", MAC: "02:00:00:00:00:09", Enabled: true})
	add.create(t, &models.InterfaceZone{InstanceID: host.ID, Name: "inside", Interfaces: models.StringList{"lan0", "wg0"}})
	add.create(t, &models.BgpConfig{InstanceID: host.ID, Enabled: true, Asn: 65000, LogNeighborChanges: true,
		Networks: models.JSONList[fwconfig.BGPNetwork]{{Prefix: "192.168.1.0/24"}}})
	add.create(t, &models.BgpConfig{InstanceID: host.ID, VrfID: &vrf.ID, Asn: 65000, LogNeighborChanges: true})
	add.create(t, &models.BgpNeighbor{InstanceID: host.ID, Address: "192.0.2.1", Enabled: true, BgpPeerSettings: models.BgpPeerSettings{RemoteAs: "65001", Password: "pw"}})
	add.create(t, &models.RoutePrefixList{InstanceID: host.ID, Name: "lan", Family: "ipv4",
		Entries: models.JSONList[fwconfig.PrefixListEntry]{{Seq: 10, Action: "permit", Prefix: "192.168.0.0/16", LE: 24}}})
	soa := models.DnsSoaTemplate{Name: "std", Mname: "ns1.example.com.", Rname: "hostmaster.example.com.", Refresh: 86400, Retry: 7200, Expire: 3600000, Minimum: 3600}
	add.create(t, &soa)
	tmpl := models.DnsTemplate{Name: "std", SoaTemplateID: soa.ID, DefaultTtl: 3600,
		Nameservers: models.DnsNameserverList{{Name: "ns1.example.com."}}}
	add.create(t, &tmpl)
	zone := models.DnsZone{InstanceID: vf.ID, Name: "blue.example.com", Type: "forward", DnsTemplateID: &tmpl.ID}
	add.create(t, &zone)
	add.create(t, &models.DnsRecord{ZoneID: zone.ID, Rank: 0, Name: "www", Type: "A", Value: "192.168.2.10"})
	add.create(t, &models.DnsRecord{ZoneID: zone.ID, Rank: 1, Name: "mail", Type: "A", Value: "192.168.2.11"})
	dd := models.DyndnsClient{InstanceID: host.ID, Name: "home", Enabled: true, InterfaceID: wan.ID, Server: "", Zone: "example.com", Provider: "cloudflare",
		ProviderSettings: models.StringMap{"api_token": "tok"}}
	add.create(t, &dd)
	add.create(t, &models.DyndnsRecord{ClientID: dd.ID, Name: "home", Type: "A"})
	add.create(t, &models.Certificate{InstanceID: host.ID, Name: "gui", Enabled: true, Source: "acme", Domains: models.StringList{"fw.example.com"},
		Ca: "letsencrypt", KeyType: "ec256", Challenge: "dns-01", DyndnsClientID: &dd.ID})
	folder := models.ObjectFolder{Kind: "hosts", Name: "servers"}
	add.create(t, &folder)
	add.create(t, &models.AddressObject{Name: "web", Addresses: models.StringList{"192.168.1.10"}, FolderID: &folder.ID})
	add.create(t, &models.AddressList{Name: "dmz", Entries: models.StringList{"web", "192.168.3.0/24"}})
	add.create(t, &models.Service{Name: "app", Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 8080}}})
	ipl := models.IpList{Name: "bad", Source: fwconfig.IPListURL, Url: "https://example.com/bad.txt"}
	add.create(t, &ipl)
	add.create(t, &models.Task{Name: "bad refresh", Enabled: true, Schedule: "0 * * * *", Kind: fwconfig.TaskIPList, IpListID: &ipl.ID, FirewallID: fw.ID})
	for i, chain := range []string{"input", "forward", "input"} {
		add.create(t, &models.Rule{InstanceID: host.ID, Position: i * 10, Chain: chain, Action: "accept", Enabled: true,
			InInterfaces: models.StringList{"inside"}, SrcAddrs: models.StringList{"dmz"}, Services: models.StringList{"app"}, SynProxyWScale: 7})
	}
	add.create(t, &models.NatRule{InstanceID: host.ID, Kind: "masquerade", OutInterfaces: models.StringList{"wan0"}, Enabled: true})
	add.create(t, &models.Link{Name: "l1", InstanceAID: host.ID, InterfaceA: "to-blue", AddressesA: models.StringList{"10.255.0.1/30"},
		InstanceBID: vf.ID, InterfaceB: "to-host", AddressesB: models.StringList{"10.255.0.2/30"}})
}

// seeded is the seed's tree, and its database (the firewall).
func seeded(t *testing.T) (*testDB, *datastore.Tree) {
	t.Helper()
	db := newTestDB(t)
	tree := datastore.New(schemaRoot(t))
	seed(t, db, newAdder(t, db, tree))
	return db, tree
}

// TestRows checks that what the adder adds comes back as rows: references
// by id, JSON lists, order, names outside the tree.
func TestRows(t *testing.T) {
	db, tree := seeded(t)
	if errs := tree.Validate(); len(errs) > 0 {
		t.Fatalf("the seed is not valid: %v", errs)
	}
	v, err := Load(recOf(db), tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Instances) != 2 || v.Instances[0].Name != "host" {
		t.Fatalf("instances %+v", v.Instances)
	}
	host := v.Instances[0]
	var fw models.Firewall
	for _, f := range v.Firewalls {
		if f.Name == "fw1" {
			fw = f
		}
	}
	if host.FirewallID != fw.ID || len(v.Tasks) != 1 || v.Tasks[0].FirewallID != fw.ID {
		t.Errorf("firewall %d: host on %d, tasks %+v", fw.ID, host.FirewallID, v.Tasks)
	}
	var red *models.Vrf
	for i := range v.Vrfs {
		if v.Vrfs[i].Name == "red" {
			red = &v.Vrfs[i]
		}
	}
	if red == nil || len(v.Routes) != 1 || v.Routes[0].VrfID == nil || *v.Routes[0].VrfID != red.ID {
		t.Errorf("route %+v, vrf %+v", v.Routes, red)
	}
	lan := ByID(v.Interfaces, *v.Routes[0].InterfaceID)
	if lan == nil || lan.Name != "lan0" || !slices.Equal(lan.Addresses, models.StringList{"192.168.1.1/24"}) {
		t.Errorf("the route's interface %+v", lan)
	}
	if len(v.DnsZones) != 1 || v.DnsZones[0].DnsTemplateID == nil || ByID(v.DnsTemplates, *v.DnsZones[0].DnsTemplateID) == nil {
		t.Errorf("zone %+v", v.DnsZones)
	}
	if len(v.DnsRecords) != 2 || v.DnsRecords[0].Name != "www" || v.DnsRecords[1].Rank != 1 {
		t.Errorf("records %+v", v.DnsRecords)
	}
	if len(v.Rules) != 3 || v.Rules[1].Chain != "forward" || !slices.Equal(v.Rules[0].SrcAddrs, models.StringList{"dmz"}) {
		t.Errorf("rules %+v", v.Rules)
	}
	if len(v.RoutePrefixLists) != 1 || len(v.RoutePrefixLists[0].Entries) != 1 || v.RoutePrefixLists[0].Entries[0].LE != 24 {
		t.Errorf("prefix lists %+v", v.RoutePrefixLists)
	}
	if len(v.WgPeers) != 1 || ByID(v.Interfaces, v.WgPeers[0].InterfaceID).Name != "wg0" {
		t.Errorf("peers %+v", v.WgPeers)
	}
	if wg := ByID(v.Interfaces, v.WgPeers[0].InterfaceID); wg.WgPrivateKey != wgKey {
		t.Error("the secret did not come through")
	}
	if v.DyndnsClients[0].ProviderSettings["api_token"] != "tok" {
		t.Errorf("provider settings %+v", v.DyndnsClients[0].ProviderSettings)
	}
	if len(v.AddressObjects) != 1 || v.AddressObjects[0].FolderID == nil || ByID(v.ObjectFolders, *v.AddressObjects[0].FolderID) == nil {
		t.Errorf("host's folder %+v", v.AddressObjects)
	}

	// The tree's JSON makes the same rows.
	data, err := tree.JSON(datastore.JSONOptions{Secrets: true})
	if err != nil {
		t.Fatal(err)
	}
	back := datastore.New(schemaRoot(t))
	if err := back.UnmarshalJSON(data); err != nil {
		t.Fatal(err)
	}
	ids, err := assign(t, db, tree)
	if err != nil {
		t.Fatal(err)
	}
	v1, _ := LoadWith(tree, ids)
	v2, _ := LoadWith(back, ids)
	v1.Tree, v1.Index, v2.Tree, v2.Index = nil, nil, nil, nil
	if !reflect.DeepEqual(v1, v2) {
		t.Error("the tree's JSON makes other rows")
	}
}

func schemaRoot(t *testing.T) *schema.Node {
	t.Helper()
	root, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func recOf(db *testDB) *records.Files { return db.rec }

// assign gives tree's entries their ids, and returns all the ids kept.
func assign(t *testing.T, db *testDB, tree *datastore.Tree) (sqlmap.IDs, error) {
	t.Helper()
	if err := recOf(db).FollowChange(testMapping(t), tree); err != nil {
		return sqlmap.IDs{}, err
	}
	return recOf(db).IDs()
}

// TestIDs: an entry keeps its id across a rename, a new one gets another,
// and one made again where one was deleted gets that one's back.
func TestIDs(t *testing.T) {
	db, tree := seeded(t)
	if _, err := assign(t, db, tree); err != nil {
		t.Fatal(err)
	}
	idOf := func(tr *datastore.Tree, p datastore.Path) uint {
		t.Helper()
		v, err := Load(recOf(db), tr)
		if err != nil {
			t.Fatal(err)
		}
		id, ok := v.ID(p)
		if !ok {
			t.Fatalf("%v has no id", p)
		}
		return id
	}
	at := func(name string) datastore.Path {
		return datastore.Path{{Name: "interface", Keys: []string{name}}}
	}
	lan, wan := idOf(tree, at("lan0")), idOf(tree, at("wan0"))
	if lan == wan || lan == 0 {
		t.Fatalf("ids %d %d", lan, wan)
	}
	if err := tree.Rename(at("lan0"), []string{"lan1"}); err != nil {
		t.Fatal(err)
	}
	if err := tree.EditJSON(datastore.Path{{Name: "interface"}}, datastore.EditCreate,
		[]byte(`{"name": "dmz0", "kind": "physical"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := assign(t, db, tree); err != nil {
		t.Fatal(err)
	}
	tree.Renamed = nil
	if got := idOf(tree, at("lan1")); got != lan {
		t.Errorf("renamed: id %d, was %d", got, lan)
	}
	dmz := idOf(tree, at("dmz0"))
	if dmz == lan || dmz == wan {
		t.Errorf("a new entry got id %d", dmz)
	}
	if err := tree.Delete(at("dmz0")); err != nil {
		t.Fatal(err)
	}
	if _, err := assign(t, db, tree); err != nil {
		t.Fatal(err)
	}
	if err := tree.EditJSON(datastore.Path{{Name: "interface"}}, datastore.EditCreate,
		[]byte(`{"name": "dmz0", "kind": "physical"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := assign(t, db, tree); err != nil {
		t.Fatal(err)
	}
	if got := idOf(tree, at("dmz0")); got != dmz {
		t.Errorf("made again: id %d, was %d", got, dmz)
	}
}

// notMapped are fields of the models that are not leaves.
var notMapped = map[string][]string{
	"settings": {"last_commit", "web_certificate_id"},
	// The runtime values (sessions.json), not configuration.
	"users": {"token_version", "totp_last_step", "totp_pending"},
	// The generation of the last deployment: runtime.
	"firewalls": {"generation"},
	// The host's: the top level's row (Load sets them).
	"instances": {"is_default"},
}

// TestEveryFieldMapped keeps the YANG modules and the models in step: a
// model's field needs its leaf (or a place above), and a row's column its
// field, or the rows lose it.
func TestEveryFieldMapped(t *testing.T) {
	m := testMapping(t)
	rv := reflect.TypeFor[View]()
	for i := range rv.NumField() {
		f := rv.Field(i)
		if f.Type.Kind() != reflect.Slice || f.Type.Elem().Kind() != reflect.Struct {
			continue
		}
		checkFields(t, m, reflect.New(f.Type.Elem()).Interface())
	}
	checkFields(t, m, &models.Settings{})
}

func checkFields(t *testing.T, m *sqlmap.Mapping, model any) {
	t.Helper()
	table, all := Columns(model)
	cols := m.Columns(table)
	if cols == nil {
		t.Errorf("table %s has no list in the YANG modules (px:table)", table)
		return
	}
	var fields []string
	for _, c := range all {
		if c == "created_at" || c == "updated_at" || slices.Contains(notMapped[table], c) {
			continue
		}
		fields = append(fields, c)
		if !slices.Contains(cols, c) {
			t.Errorf("%s.%s has no leaf in the YANG modules", table, c)
		}
	}
	for _, c := range cols {
		if !slices.Contains(fields, c) {
			t.Errorf("%s: column %s has no field in the model", table, c)
		}
	}
}

// wgKey is wg0's private key, a secret.
var wgKey string

// A rename whose commit was refused is put back: so is the entry's id.
func TestUndoRenames(t *testing.T) {
	db, tree := seeded(t)
	if _, err := assign(t, db, tree); err != nil {
		t.Fatal(err)
	}
	at := func(name string) datastore.Path {
		return datastore.Path{{Name: "interface", Keys: []string{name}}}
	}
	ids, _ := recOf(db).IDs()
	was := func(p datastore.Path) int64 { id, _ := ids.ID(p.String(tree.Root.S)); return id }
	lan := was(at("lan0"))
	if lan == 0 {
		t.Fatal("no id")
	}
	if err := tree.Rename(at("lan0"), []string{"lan1"}); err != nil {
		t.Fatal(err)
	}
	renamed := append([]datastore.Renamed(nil), tree.Renamed...)
	if _, err := assign(t, db, tree); err != nil {
		t.Fatal(err)
	}
	ids, _ = recOf(db).IDs()
	if was(at("lan1")) != lan || was(at("lan0")) != 0 {
		t.Fatalf("not moved: %d %d", was(at("lan1")), was(at("lan0")))
	}
	if err := recOf(db).UpdateIDs(func(ids sqlmap.IDs) { testMapping(t).UndoRenames(ids, renamed) }); err != nil {
		t.Fatal(err)
	}
	ids, _ = recOf(db).IDs()
	if was(at("lan0")) != lan || was(at("lan1")) != 0 {
		t.Errorf("not put back: %d %d", was(at("lan0")), was(at("lan1")))
	}
}
