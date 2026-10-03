// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

// FRR 8 and later: neighbours by router id, each a list.
const ospfNeighborsJSON = `{"neighbors":{"10.0.0.2":[{"nbrPriority":1,"nbrState":"Full/DR","converged":"Full","role":"DR",
"upTime":"1m02s","routerDeadIntervalTimerDueMsec":33000,"deadTime":"33.000s","ifaceAddress":"10.255.0.1","ifaceName":"lk-main:10.255.0.2"}],
"10.0.0.3":[{"priority":0,"state":"2-Way/DROther","deadTimeMsecs":38000,"address":"10.255.0.5","ifaceName":"eth2:192.168.50.1"}]}}`

const ospf6NeighborsJSON = `{"neighbors":[{"neighborId":"10.0.0.2","priority":1,"deadTime":"00:00:35","state":"Full","ifState":"DR",
"duration":"00:01:00","interfaceName":"lk-main","interfaceState":"BDR"}]}`

const ospfInterfacesJSON = `{"interfaces":{"lk-main":{"ifUp":true,"ospfEnabled":true,"ipAddress":"10.255.0.2","ipAddressPrefixlen":30,
"area":"0.0.0.0","networkType":"POINTOPOINT","cost":10,"state":"Point-To-Point","priority":1,"nbrCount":1,"nbrAdjacentCount":1},
"eth2":{"ifUp":true,"ospfEnabled":true,"ipAddress":"192.168.50.1","ipAddressPrefixlen":24,"area":"0.0.0.1 [Stub]","networkType":"BROADCAST",
"cost":100,"state":"DR","priority":0,"timerPassiveIface":true,"drId":"10.0.0.1","nbrCount":0,"nbrAdjacentCount":0},
"eth0":{"ifUp":true,"ospfEnabled":false}}}`

const ospf6InterfacesJSON = `{"interfaces":{"lk-main":{"status":"up","type":"POINTOPOINT","attachedToArea":true,"areaId":"0.0.0.0",
"cost":10,"state":"PointToPoint","priority":1,"internetAddress":[{"type":"inet6","address":"fe80::1"},{"type":"inet6","address":"2001:db8::2"}]},
"eth2":{"status":"up","attachedToArea":false}}}`

const ospfRoutesJSON = `{"10.255.0.0/30":{"routeType":"N","cost":10,"area":"0.0.0.0","nexthops":[{"ip":" ","directlyAttachedTo":"lk-main"}]},
"192.168.0.0/16":{"routeType":"N E2","cost":20,"type2cost":20,"nexthops":[{"ip":"10.255.0.1","via":"lk-main"}]},
"10.0.0.2":{"routeType":"R ","cost":10,"area":"0.0.0.0","routerType":"asbr","nexthops":[{"ip":"10.255.0.1","via":"lk-main"}]}}`

const ospf6RoutesJSON = `{"routes":{"2001:db8:1::/64":{"isBestRoute":true,"destinationType":"N","pathType":"IE","duration":"00:01:00",
"nextHops":[{"nextHop":"fe80::2","interfaceName":"lk-main"}]}}}`

func TestParseOSPF(t *testing.T) {
	n := parseOSPFNeighbors([]byte(ospfNeighborsJSON), 2)
	if len(n) != 2 {
		t.Fatalf("%+v", n)
	}
	if n[0].RouterID != "10.0.0.2" || n[0].State != "Full" || n[0].Role != "DR" || n[0].Interface != "lk-main" ||
		n[0].Address != "10.255.0.1" || n[0].Uptime != "1m02s" || n[0].DeadTime != "33.000s" || n[0].Priority != 1 {
		t.Errorf("%+v", n[0])
	}
	if n[1].State != "2-Way" || n[1].Role != "DROther" || n[1].Interface != "eth2" || n[1].Address != "10.255.0.5" {
		t.Errorf("FRR 7: %+v", n[1])
	}
	n6 := parseOSPFNeighbors([]byte(ospf6NeighborsJSON), 3)
	if len(n6) != 1 || n6[0].RouterID != "10.0.0.2" || n6[0].State != "Full" || n6[0].Role != "DR" || n6[0].Interface != "lk-main" || n6[0].Uptime != "00:01:00" {
		t.Errorf("%+v", n6)
	}

	ifs := parseOSPFInterfaces([]byte(ospfInterfacesJSON), 2)
	if len(ifs) != 2 || ifs[0].Name != "eth2" || ifs[0].Area != "0.0.0.1" || !ifs[0].Passive || ifs[0].Address != "192.168.50.1/24" ||
		ifs[1].Name != "lk-main" || ifs[1].Adjacent != 1 || ifs[1].Cost != 10 {
		t.Errorf("%+v", ifs)
	}
	ifs6 := parseOSPFInterfaces([]byte(ospf6InterfacesJSON), 3)
	if len(ifs6) != 1 || ifs6[0].Address != "2001:db8::2" || ifs6[0].NetworkType != "POINTOPOINT" {
		t.Errorf("%+v", ifs6)
	}

	r := parseOSPFRoutes([]byte(ospfRoutesJSON))
	if len(r) != 2 || r[0].Prefix != "10.255.0.0/30" || r[0].Type != "intra-area" || r[0].NextHops[0] != "directly attached" ||
		r[0].Interface[0] != "lk-main" || *r[0].Cost != 10 || r[1].Type != "external 2" || r[1].NextHops[0] != "10.255.0.1" {
		t.Errorf("%+v", r)
	}
	r6 := parseOSPFRoutes([]byte(ospf6RoutesJSON))
	if len(r6) != 1 || r6[0].Type != "inter-area" || r6[0].NextHops[0] != "fe80::2" || r6[0].Cost != nil {
		t.Errorf("%+v", r6)
	}

	// ospfd counts per area; ospf6d's areas are counted from the
	// interfaces and neighbours.
	router, _ := parseJSONObj([]byte(`{"routerId":"10.0.0.1","areas":{"0.0.0.0":{"areaIfTotalCounter":1,"nbrFullAdjacentCounter":1,"lsaNumber":4},
"0.0.0.1":{"stubNoSummary":true,"areaIfTotalCounter":1,"nbrFullAdjacentCounter":0,"lsaNumber":2}}}`))
	a := ospfAreas(router, ifs, n)
	if len(a) != 2 || a[0].FullAdjacencies != 1 || a[0].LSAs != 4 || a[1].Type != "stub" || a[1].Interfaces != 1 {
		t.Errorf("%+v", a)
	}
	router6, _ := parseJSONObj([]byte(`{"routerId":"10.0.0.1","areas":{"0.0.0.0":{"numberOfAreaScopedLsa":3}}}`))
	a6 := ospfAreas(router6, ifs6, n6)
	if len(a6) != 1 || a6[0].Interfaces != 1 || a6[0].FullAdjacencies != 1 || a6[0].LSAs != 3 {
		t.Errorf("%+v", a6)
	}
}

func TestOSPFState(t *testing.T) {
	st := ospfState(func(cmd string) ([]byte, error) {
		switch cmd {
		case "show ipv6 ospf6 json":
			return []byte(`{"routerId":"10.0.0.1","areas":{}}`), nil
		case "show ipv6 ospf6 interface json":
			return []byte(ospf6InterfacesJSON), nil
		case "show ipv6 ospf6 neighbor json":
			return []byte(ospf6NeighborsJSON), nil
		case "show ipv6 ospf6 route json":
			return []byte(ospf6RoutesJSON), nil
		}
		t.Errorf("asked %q", cmd)
		return nil, errors.New("no")
	}, 3)
	if st.Error != "" || st.RouterID != "10.0.0.1" || len(st.Interfaces) != 1 || len(st.Neighbors) != 1 || len(st.Routes) != 1 || st.Areas == nil {
		t.Errorf("%+v", st)
	}
	// ospfd not running: vtysh's complaint is the error.
	st = ospfState(func(string) ([]byte, error) {
		return []byte("% OSPF instance not found\n"), errors.New("exit status 1")
	}, 2)
	if st.Error != "% OSPF instance not found" || st.Neighbors == nil {
		t.Errorf("%+v", st)
	}
}

// Only the versions an instance runs are asked for.
func TestAgentOSPF(t *testing.T) {
	a, _ := testAgent(t)
	r := &vtyshRunner{Runner: a.bg}
	a.bg = r
	doc := fwconfig.SampleDocument()
	doc.Instance("guest").OSPF6 = nil
	a.applied = &doc
	resp := a.OSPF(context.Background())
	if len(resp.Instances) != 1 || resp.Instances[0].Instance != "guest" || resp.Instances[0].V2 == nil || resp.Instances[0].V3 != nil {
		t.Fatalf("%+v", resp)
	}
	if !r.ran("vtysh", "-N", "guest", "-c", "show ip ospf neighbor json") {
		t.Errorf("calls %v", r.calls)
	}
	for _, c := range r.calls {
		if strings.Contains(strings.Join(c, " "), "ospf6") {
			t.Errorf("asked OSPFv3: %v", c)
		}
	}
}
