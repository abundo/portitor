// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	dnsmgr "github.com/abundo/dnsmgr2/dnsmgr"
	"gopkg.in/yaml.v3"

	"github.com/abundo/portitor/internal/fwconfig"
)

func sampleBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := Render(fwconfig.SampleDocument(), Options{
		Paths:       DefaultPaths(),
		Units:       DefaultUnits(),
		AntiLockout: &AntiLockout{Port: 8443, AllowFrom: []string{"192.168.1.0/24", "fd00:1::/64"}},
		DHCPDNS:     map[string][]string{"main": {"198.51.100.53"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustFile(t *testing.T, b *Bundle, path string) string {
	t.Helper()
	f := b.File(path)
	if f == nil {
		var paths []string
		for _, f := range b.Files {
			paths = append(paths, f.Path)
		}
		t.Fatalf("no file %s; have %v", path, paths)
	}
	return f.Content
}

func TestNftablesMain(t *testing.T) {
	nft := mustFile(t, sampleBundle(t), "/etc/portitor/instances/main/nftables.nft")
	for _, want := range []string{
		"delete table inet firewall",
		`ip saddr 192.168.1.0/24 tcp dport 8443 accept comment "anti-lockout"`,
		`ip6 saddr fd00:1::/64 tcp dport 8443 accept comment "anti-lockout"`,
		`iifname "eth0" udp sport 67 udp dport 68 accept comment "auto: dhcp client"`,
		`iifname { "eth1", "eth1.20" } udp dport 67 accept`,
		`iifname { "eth1", "eth1.20", "wg0" } meta l4proto { tcp, udp } th dport 53 accept`,
		`udp dport 51820 accept comment "auto: wireguard wg0"`,
		`iifname "eth1" oifname "eth0" counter accept comment "rule 1: LAN to Internet"`,
		`iifname "eth1.20" oifname "eth0" tcp dport { 80, 443, 8883 } counter accept`,
		`iifname "lk-guest" oifname "eth0" counter accept`,
		`iifname "eth0" ip daddr 192.168.1.0/24 counter log prefix "fw rule 7 drop: " drop comment "rule 7: no 'direct' access"`,
		`iifname vmap { "eth0" : drop, "eth1" : accept, "eth1.20" : jump reject_pkt, "lk-guest" : drop, "wg0" : accept }`,
		`iifname "eth0" meta nfproto ipv4 tcp dport 8443 counter dnat ip to 192.168.1.10:443 comment "nat 1: NAS"`,
		`oifname "eth0" meta nfproto ipv4 counter masquerade comment "zone wan"`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n  %s\nin:\n%s", want, nft)
		}
	}
	// Input rules are in the input chain, forward rules in forward.
	in := nft[strings.Index(nft, "chain input {"):strings.Index(nft, "chain forward {")]
	if !strings.Contains(in, "rule 5: ping") || strings.Contains(in, "rule 1:") {
		t.Errorf("rules in wrong chain:\n%s", in)
	}
}

func TestNftablesGuestHasNoLockout(t *testing.T) {
	nft := mustFile(t, sampleBundle(t), "/etc/portitor/instances/guest/nftables.nft")
	if strings.Contains(nft, "anti-lockout") {
		t.Error("anti-lockout belongs to the default instance only")
	}
	if !strings.Contains(nft, `oifname "lk-main" ip daddr 192.168.0.0/16 counter jump reject_pkt`) {
		t.Errorf("guest reject rule missing:\n%s", nft)
	}
}

// TestNftablesSyntax runs the rendered rulesets through `nft -c` in an
// unprivileged user+network namespace, when the host allows that.
func TestNftablesSyntax(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not installed")
	}
	if out, err := exec.Command("unshare", "-rn", "nft", "list", "ruleset").CombinedOutput(); err != nil {
		t.Skipf("cannot run nft in a user namespace: %v %s", err, out)
	}
	b := sampleBundle(t)
	for _, f := range b.Files {
		if !strings.HasSuffix(f.Path, ".nft") {
			continue
		}
		path := filepath.Join(t.TempDir(), "rules.nft")
		if err := os.WriteFile(path, []byte(f.Content), 0o600); err != nil {
			t.Fatal(err)
		}
		// The ruleset refers to the interfaces only by name, and the
		// leading "delete table" needs the table to exist.
		if out, err := exec.Command("unshare", "-rn", "nft", "-c", "-f", path).CombinedOutput(); err != nil {
			t.Errorf("%s: nft -c failed: %v\n%s\n%s", f.Path, err, out, f.Content)
		}
	}
}

func TestWireGuard(t *testing.T) {
	b := sampleBundle(t)
	f := b.File("/etc/portitor/instances/main/wireguard/wg0.conf")
	if f == nil || f.Mode != 0o600 || !f.Secret {
		t.Fatalf("wg0.conf: %+v", f)
	}
	for _, want := range []string{"ListenPort = 51820", "# phone", "AllowedIPs = 10.99.0.2/32"} {
		if !strings.Contains(f.Content, want) {
			t.Errorf("missing %q in\n%s", want, f.Content)
		}
	}
	for _, r := range b.Redacted() {
		if strings.Contains(r.Content, "YEocP0e2o1WT5GlvBvQzVF7EeR6z9aCk8ZdZ5oPr1Wk=") {
			t.Errorf("%s: private key not redacted", r.Path)
		}
	}
}

func TestNamedConf(t *testing.T) {
	named := mustFile(t, sampleBundle(t), "/etc/portitor/instances/main/named.conf")
	for _, want := range []string{
		"listen-on port 53 { 127.0.0.1; 192.168.1.1; 192.168.20.1; 10.99.0.1; };",
		"listen-on-v6 port 53 { ::1; fd00:1::1; };",
		"allow-recursion { localhost; 192.168.1.0/24; fd00:1::/64; 192.168.20.0/24; 10.99.0.0/24; };",
		"forwarders { 9.9.9.9; 198.51.100.53; };",
		`include "/etc/portitor/instances/main/named.conf.dnsmgr2";`,
		"dnssec-policy \"signed\" {\n\tkeys {\n\t\tksk lifetime unlimited algorithm ecdsap256sha256;\n\t\tzsk lifetime P90D algorithm ecdsap256sha256;\n\t};\n\tsignatures-validity 14d;\n};",
	} {
		if !strings.Contains(named, want) {
			t.Errorf("missing %q in\n%s", want, named)
		}
	}
}

func TestDnsmgrAndKea(t *testing.T) {
	b := sampleBundle(t)
	cfg := b.Dnsmgr["main"]
	if len(cfg.Dnsmgr2) != 1 || len(cfg.Dnsmgr2[0].Zones) != 2 || len(cfg.Dnsmgr2[0].Prefixes) != 2 {
		t.Fatalf("dnsmgr2 config: %+v", cfg.Dnsmgr2)
	}
	// home.arpa uses the "home" template; the reverse zone the built-in one.
	zones := cfg.Dnsmgr2[0].Zones
	if zones[0].DnsTemplate != "tpl-home" || zones[1].DnsTemplate != "firewall" {
		t.Errorf("zone templates: %+v", zones)
	}
	zt := cfg.DNS.ZoneTemplates["tpl-home"]
	if zt.SOA != "soa-home" || zt.DefaultTTL != "3600" || zt.DNSSECpolicy != "signed" ||
		len(zt.NS) != 1 || zt.NS[0].Value != "gw.home.arpa." {
		t.Errorf("zone template: %+v", zt)
	}
	if soa := cfg.DNS.SOATemplates["soa-home"]; soa.Mname != "gw.home.arpa." || soa.Rname != "hostmaster.home.arpa." || soa.Minimum != 3600 {
		t.Errorf("soa template: %+v", soa)
	}
	if got := cfg.Dnsmgr2[0].Prefixes[0].Range; got != "192.168.1.100-192.168.1.199" {
		t.Errorf("range %q", got)
	}
	// Guest runs DHCP without DNS: no zones, no DNS host template.
	g := b.Dnsmgr["guest"]
	if g.Dnsmgr2[0].HostDnsTemplate != "" || len(g.Dnsmgr2[0].Zones) != 0 {
		t.Errorf("guest dnsmgr2: %+v", g.Dnsmgr2[0])
	}
	if b.File("/etc/portitor/instances/guest/named.conf") != nil {
		t.Error("guest has DNS disabled but got a named.conf")
	}

	var records struct {
		Domains []struct {
			Name    string
			Records []map[string]any
		}
	}
	if err := json.Unmarshal([]byte(mustFile(t, b, "/etc/portitor/instances/main/records.json")), &records); err != nil {
		t.Fatal(err)
	}
	if len(records.Domains) != 1 || records.Domains[0].Records[1]["mac"] != "02:00:00:00:00:10" {
		t.Errorf("records: %+v", records)
	}

	kea := mustFile(t, b, "/etc/portitor/instances/main/kea-dhcp4.conf")
	for _, want := range []string{
		`"interfaces": ["eth1","eth1.20"]`,
		`"valid-lifetime": 43200`,
		`"name": "/var/lib/kea/kea-leases4-main.csv"`,
		`<?include "/etc/portitor/instances/main/kea-dhcp4.dnsmgr2.json"?>`,
	} {
		if !strings.Contains(kea, want) {
			t.Errorf("missing %q in\n%s", want, kea)
		}
	}
}

func TestIPv6Services(t *testing.T) {
	b := sampleBundle(t)
	nft := mustFile(t, b, "/etc/portitor/instances/main/nftables.nft")
	for _, want := range []string{
		`iifname "eth1" udp dport 547 accept comment "auto: dhcpv6 server"`,
		// A rule with both IPv4 and IPv6 addresses becomes one per version.
		`iifname "wg0" ip daddr 192.168.1.10 tcp dport 22 counter accept comment "rule 8: NAS ssh"`,
		`iifname "wg0" ip6 daddr fd00:1::10 tcp dport 22 counter accept comment "rule 8: NAS ssh"`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n  %s\nin:\n%s", want, nft)
		}
	}
	// The DHCPv4 server rule stays on the IPv4 subnets' interfaces.
	if !strings.Contains(nft, `iifname { "eth1", "eth1.20" } udp dport 67 accept`) {
		t.Errorf("dhcpv4 rule changed:\n%s", nft)
	}

	radvd := mustFile(t, b, "/etc/portitor/instances/main/radvd.conf")
	for _, want := range []string{
		"interface eth1 {", "AdvManagedFlag on;", "AdvOtherConfigFlag on;",
		"prefix fd00:1::/64 {", "AdvAutonomous on;", "RDNSS fd00:1::1 {", "DNSSL home.arpa {",
	} {
		if !strings.Contains(radvd, want) {
			t.Errorf("radvd.conf lacks %q:\n%s", want, radvd)
		}
	}

	conf := mustFile(t, b, "/etc/portitor/instances/main/kea-dhcp6.conf")
	var kea struct {
		Dhcp6 struct {
			InterfacesConfig struct{ Interfaces []string } `json:"interfaces-config"`
			LeaseDatabase    struct{ Name string }         `json:"lease-database"`
			Subnet6          []struct {
				ID           int
				Subnet       string
				Interface    string
				Pools        []struct{ Pool string }
				OptionData   []struct{ Name, Data string } `json:"option-data"`
				Reservations []struct {
					HWAddress   string   `json:"hw-address"`
					IPAddresses []string `json:"ip-addresses"`
					Hostname    string
				}
			}
		}
	}
	// Kea allows the leading comment line; encoding/json does not.
	if err := json.Unmarshal([]byte(conf[strings.Index(conf, "\n"):]), &kea); err != nil {
		t.Fatalf("kea-dhcp6.conf is not JSON: %v\n%s", err, conf)
	}
	d := kea.Dhcp6
	if len(d.InterfacesConfig.Interfaces) != 1 || d.InterfacesConfig.Interfaces[0] != "eth1" || d.LeaseDatabase.Name != "/var/lib/kea/kea-leases6-main.csv" {
		t.Errorf("dhcp6 globals: %+v", d)
	}
	if len(d.Subnet6) != 1 {
		t.Fatalf("subnet6: %+v", d.Subnet6)
	}
	sn := d.Subnet6[0]
	if sn.Subnet != "fd00:1::/64" || sn.Interface != "eth1" || len(sn.Pools) != 1 || sn.Pools[0].Pool != "fd00:1::1000 - fd00:1::1fff" {
		t.Errorf("subnet: %+v", sn)
	}
	if len(sn.OptionData) != 2 || sn.OptionData[0].Data != "fd00:1::1" || sn.OptionData[1].Data != "home.arpa" {
		t.Errorf("options: %+v", sn.OptionData)
	}
	if len(sn.Reservations) != 1 || sn.Reservations[0].HWAddress != "02:00:00:00:00:10" ||
		sn.Reservations[0].IPAddresses[0] != "fd00:1::10" || sn.Reservations[0].Hostname != "nas.home.arpa" {
		t.Errorf("reservations: %+v", sn.Reservations)
	}

	// The guest instance has no IPv6 services.
	for _, f := range []string{"radvd.conf", "kea-dhcp6.conf"} {
		if b.File("/etc/portitor/instances/guest/"+f) != nil {
			t.Errorf("guest got %s", f)
		}
	}
}

func TestNATPerFamily(t *testing.T) {
	doc := fwconfig.SampleDocument()
	in := &doc.Instances[0]
	in.NAT = append(in.NAT,
		// Source list mixes versions; the IPv4 target keeps the IPv4 part.
		fwconfig.NATRule{Kind: fwconfig.NATSNAT, OutZone: "wan", SrcAddrs: []string{"192.168.1.0/24", "fd00:1::/64"}, ToAddr: "198.51.100.7"},
		fwconfig.NATRule{Kind: fwconfig.NATMasquerade, OutZone: "wan", SrcAddrs: []string{"fd00:1::/64"}},
	)
	b, err := Render(doc, Options{Paths: DefaultPaths(), Units: DefaultUnits()})
	if err != nil {
		t.Fatal(err)
	}
	nft := mustFile(t, b, "/etc/portitor/instances/main/nftables.nft")
	for _, want := range []string{
		`oifname "eth0" ip saddr 192.168.1.0/24 counter snat ip to 198.51.100.7 comment "nat 2"`,
		`oifname "eth0" ip6 saddr fd00:1::/64 counter masquerade comment "nat 3"`,
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing:\n  %s\nin:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "ip6 saddr fd00:1::/64 counter snat") {
		t.Error("snat to an IPv4 target must not match IPv6 sources")
	}
}

func TestRenderRejectsInvalid(t *testing.T) {
	doc := fwconfig.SampleDocument()
	doc.Instances[0].Interfaces[0].Name = "eth0\"; flush ruleset"
	if _, err := Render(doc, Options{Paths: DefaultPaths(), Units: DefaultUnits()}); err == nil {
		t.Fatal("expected validation error")
	}
}

// dnsmgr2.yaml is the whole dnsmgr2 config (templates and zones in one
// file); loaded by dnsmgr2 itself it must equal what the agent syncs.
func TestDnsmgrYAMLRoundTrip(t *testing.T) {
	b := sampleBundle(t)
	for name, want := range b.Dnsmgr {
		path := filepath.Join(t.TempDir(), "dnsmgr2.yaml")
		if err := os.WriteFile(path, []byte(mustFile(t, b, "/etc/portitor/instances/"+name+"/dnsmgr2.yaml")), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := dnsmgr.LoadConfigFile(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Compared as YAML: nil and empty lists load back the same.
		g, _ := yaml.Marshal(got)
		w, _ := yaml.Marshal(want)
		if string(g) != string(w) {
			t.Errorf("%s: dnsmgr2.yaml does not round-trip\ngot\n%s\nwant\n%s", name, g, w)
		}
	}
}
