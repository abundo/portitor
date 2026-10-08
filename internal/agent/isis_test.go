// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"errors"
	"strings"
	"testing"
)

func TestISISInstance(t *testing.T) {
	answers := map[string]string{
		"show isis summary json": `{"vrf":"default","process-id":123,"areas":[{"area":"portitor","system-id":"0102.5500.0002"}]}`,
		"show isis neighbor json": `{"areas":[{"area":"portitor","circuits":[
			{"circuit":0,"adj":"r2","interface":"lk-main","level":2,"state":"Up","expires-in":"28s","snpa":"2ca9.4f3c.0c02"},
			{"circuit":1,"adj":"0000.0000.0009","interface":"eth2","level":1,"state":"Initializing"}]}]}`,
		"show isis interface json": `{"areas":[{"area":"portitor","circuits":[
			{"circuit":0,"interface":{"name":"lk-main","circuit-id":"0x0","state":"Up","type":"p2p","level":"L2"}},
			{"circuit":1,"interface":{"name":"eth2","state":"Up","type":"lan","level":"L1L2"}}]}]}`,
		"show isis route json": `{"areas":[{"area":"portitor","levels":[{"id":2,
			"ipv4-paths":[{"Prefix":"10.0.0.0/24","Metric":"20","Interface":"lk-main","Nexthop":"10.255.0.1"},
				{"Prefix":"","Metric":"","Interface":"eth2","Nexthop":"192.168.50.9"},
				{"Prefix":"10.255.0.0/30","Metric":10,"Interface":"lk-main","Nexthop":"-"}],
			"ipv6-paths":[{"Prefix":"2001:db8::/64","Metric":"20","Interface":"lk-main","Nexthop":"fe80::1"}]}]}]}`,
	}
	vtysh := func(cmd string) ([]byte, error) {
		if s, ok := answers[cmd]; ok {
			return []byte(s), nil
		}
		return nil, errors.New("unknown command")
	}
	st := isisInstance("guest", vtysh)
	if st.Error != "" || st.SystemID != "0102.5500.0002" {
		t.Fatalf("%+v", st)
	}
	if len(st.Neighbors) != 2 || st.Neighbors[1].SystemID != "r2" || st.Neighbors[1].Level != "L2" || st.Neighbors[1].State != "Up" ||
		st.Neighbors[1].HoldTime != "28s" || st.Neighbors[0].Interface != "eth2" {
		t.Errorf("neighbours %+v", st.Neighbors)
	}
	if len(st.Interfaces) != 2 || st.Interfaces[1].Name != "lk-main" || st.Interfaces[1].Type != "p2p" || st.Interfaces[0].Level != "L1L2" {
		t.Errorf("interfaces %+v", st.Interfaces)
	}
	if len(st.Routes) != 3 {
		t.Fatalf("routes %+v", st.Routes)
	}
	r := st.Routes[0]
	if r.Prefix != "10.0.0.0/24" || r.Level != "L2" || r.Metric == nil || *r.Metric != 20 ||
		strings.Join(r.NextHops, ",") != "10.255.0.1,192.168.50.9" || strings.Join(r.Interface, ",") != "lk-main,eth2" {
		t.Errorf("route %+v", r)
	}
	if r := st.Routes[1]; r.Prefix != "10.255.0.0/30" || *r.Metric != 10 || r.NextHops[0] != "directly attached" {
		t.Errorf("route %+v", r)
	}

	// isisd not answering.
	st = isisInstance("guest", func(string) ([]byte, error) { return []byte("isisd is not running"), errors.New("exit status 1") })
	if st.Error == "" {
		t.Error("no error")
	}
}
