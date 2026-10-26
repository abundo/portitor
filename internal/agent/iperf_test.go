// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestIperfArgs(t *testing.T) {
	in := &fwconfig.Instance{Name: "main", Interfaces: []fwconfig.Interface{{Name: "wan"}}}
	req := agentapi.IperfRequest{Mode: "client", Interface: "wan", Target: "2001:db8::1", Protocol: "udp", Direction: "both", Bitrate: 50_000_000, Streams: 4}
	argv, err := iperfArgs(in, &req)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"iperf3", "--json-stream", "--forceflush", "--interval", "1", "--client", "2001:db8::1", "--port", "5201",
		"--time", "10", "--parallel", "4", "--connect-timeout", "5000", "--udp", "--bidir", "--bitrate", "50000000", "-6", "--bind-dev", "wan"}
	if !slices.Equal(argv, want) {
		t.Errorf("argv %q", argv)
	}
	srv := agentapi.IperfRequest{Mode: "server", Port: 5300, OneOff: true, Family: "ipv4"}
	argv, err = iperfArgs(in, &srv)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"iperf3", "--json-stream", "--forceflush", "--interval", "1", "--server", "--port", "5300", "--one-off", "-4"}
	if !slices.Equal(argv, want) || srv.Duration != agentapi.IperfDefaultServerDuration {
		t.Errorf("argv %q, duration %d", argv, srv.Duration)
	}
	for _, bad := range []agentapi.IperfRequest{
		{Mode: "client", Target: "example.com"},
		{Mode: "client", Target: "-x"},
		{Mode: "client", Target: "fe80::1%eth0"},
		{Mode: "client", Target: "192.0.2.1", Interface: "nope"},
		{Mode: "client", Target: "192.0.2.1", Protocol: "sctp"},
		{Mode: "client", Target: "192.0.2.1", Direction: "up"},
		{Mode: "client", Target: "192.0.2.1", Streams: 1000},
		{Mode: "client", Target: "192.0.2.1", Bitrate: -1},
		{Mode: "server", Port: 70000},
		{Mode: "server", Family: "ipx"},
		{Mode: "daemon"},
	} {
		if _, err := iperfArgs(in, &bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	big := agentapi.IperfRequest{Mode: "client", Target: "192.0.2.1", Duration: 1 << 20}
	if _, err := iperfArgs(in, &big); err != nil || big.Duration != agentapi.IperfMaxDuration {
		t.Errorf("duration %d, %v", big.Duration, err)
	}
}

func TestParseIperfLine(t *testing.T) {
	// Lines of iperf3 3.22's --json-stream, shortened.
	for line, want := range map[string]string{
		`{"event":"start","data":{"connected":[{"socket":4,"local_host":"192.0.2.2","local_port":50304,"remote_host":"::ffff:192.0.2.1","remote_port":5201}],"test_start":{"protocol":"TCP","num_streams":2,"duration":10,"reverse":0}}}`:                                                                       `{"type":"start","remote":"192.0.2.1","protocol":"tcp","duration":10,"streams":2}`,
		`{"event":"interval","data":{"streams":[],"sum":{"start":0,"end":1.000958,"seconds":1.00095796585083,"bytes":7178420224,"bits_per_second":57372400991.5,"retransmits":3,"omitted":false,"sender":true}}}`:                                                                                               `{"type":"interval","sums":[{"dir":"sent","start":0,"end":1.000958,"bytes":7178420224,"bits_per_second":57372400991.5,"retransmits":3}]}`,
		`{"event":"interval","data":{"sum":{"start":0,"end":1,"bytes":1277952,"bits_per_second":10215810.5,"packets":39,"sender":true},"sum_bidir_reverse":{"start":0,"end":1,"bytes":1277952,"bits_per_second":10215810.5,"jitter_ms":0.25,"lost_packets":1,"packets":39,"lost_percent":2.5,"sender":false}}}`: `{"type":"interval","sums":[{"dir":"sent","start":0,"end":1,"bytes":1277952,"bits_per_second":10215810.5,"packets":39},{"dir":"received","receiver":true,"start":0,"end":1,"bytes":1277952,"bits_per_second":10215810.5,"jitter_ms":0.25,"lost_packets":1,"packets":39,"lost_percent":2.5}]}`,
		// A server's end: it knows nothing of the client's sending.
		`{"event":"end","data":{"sum_sent":{"start":0,"end":2,"seconds":2,"bytes":0,"bits_per_second":0,"sender":false},"sum_received":{"start":0,"end":2,"seconds":2,"bytes":1000,"bits_per_second":4000,"sender":false}}}`: `{"type":"end","sums":[{"dir":"received","receiver":true,"start":0,"end":2,"bytes":1000,"bits_per_second":4000}]}`,
		`{"event":"error","data":"unable to connect to server: Connection refused"}`: `{"type":"error","error":"unable to connect to server: Connection refused"}`,
		`{"event":"end","data":{}}`:      ``,
		`{"event":"interval","data":{}}`: ``,
		`iperf3: error`:                  ``,
	} {
		ev, ok := parseIperfLine([]byte(line))
		got := ""
		if ok {
			b, _ := json.Marshal(ev)
			got = string(b)
		}
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", line, got, want)
		}
	}
}
