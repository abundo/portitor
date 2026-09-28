// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netobj

import (
	"reflect"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

func TestServiceNames(t *testing.T) {
	for _, s := range []string{"myapp", "web-alt", "a.b_c", "unifi2"} {
		if !ValidServiceName(s) {
			t.Errorf("%q should be a valid service name", s)
		}
	}
	for _, s := range []string{"", "ssh", "https", "ping", "any", "MyApp", "1app", "a b", "a,b", "8000-8080"} {
		if ValidServiceName(s) {
			t.Errorf("%q should not be a valid service name", s)
		}
	}
}

// TestPredefined checks every predefined service, and that the matches
// they expand to pass the agent's validation.
func TestPredefined(t *testing.T) {
	seen := map[string]bool{}
	var names []string
	for _, s := range Predefined {
		if !serviceNameRe.MatchString(s.Name) || seen[s.Name] {
			t.Errorf("bad or duplicate name %q", s.Name)
		}
		seen[s.Name] = true
		names = append(names, s.Name)
		if err := CheckService(s); err != nil {
			t.Errorf("%s: %v", s.Name, err)
		}
	}
	matches, err := NewServices(nil).Expand(names)
	if err != nil {
		t.Fatal(err)
	}
	doc := fwconfig.SampleDocument()
	doc.Instances[0].Rules[0].Services = matches
	if err := doc.Validate(); err != nil {
		t.Error(err)
	}
}

func TestCheckService(t *testing.T) {
	code := 3
	bad := []models.Service{
		{Type: "tcp"},
		{Type: models.ServiceTypePorts},
		{Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "icmp", DstLo: 1}}},
		{Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 90, DstHi: 80}}},
		{Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 70000}}},
		{Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 22, SrcHi: 5}}},
		{Type: models.ServiceTypeICMP, IcmpType: "nd-neighbor-solicit"},
		{Type: models.ServiceTypeICMP6, IcmpCode: &code},
		{Type: models.ServiceTypeIP, IpProtocol: 256},
	}
	for _, s := range bad {
		if CheckService(s) == nil {
			t.Errorf("%+v: expected an error", s)
		}
	}
}

func TestExpandServices(t *testing.T) {
	code := 4
	s := NewServices([]models.Service{
		{Name: "app", Type: models.ServiceTypePorts, Ports: models.ServicePortList{
			{Protocol: "tcp", DstLo: 8000, DstHi: 8080},
			{Protocol: "udp", DstLo: 53, SrcLo: 1024, SrcHi: 65535},
			{Protocol: "sctp"},
		}},
		{Name: "frag", Type: models.ServiceTypeICMP6, IcmpType: "destination-unreachable", IcmpCode: &code},
		{Name: "tcp53", Type: models.ServiceTypePorts, Ports: models.ServicePortList{{Protocol: "tcp", DstLo: 53, DstHi: 53}}},
	})
	got, err := s.Expand([]string{"app", "frag", "gre", "dns", "tcp53"})
	if err != nil {
		t.Fatal(err)
	}
	want := []fwconfig.ServiceMatch{
		{Protocol: "tcp", DstPorts: "8000-8080,53"},
		{Protocol: "udp", DstPorts: "53", SrcPorts: "1024-65535"},
		{Protocol: "sctp"},
		{Protocol: "icmpv6", ICMPType: "destination-unreachable", ICMPCode: &code},
		{Protocol: "ip", IPProtocol: 47},
		{Protocol: "udp", DstPorts: "53"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if _, err := s.Expand([]string{"ghost"}); err == nil {
		t.Error("expected an error for an unknown service")
	}
}
