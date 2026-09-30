// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"slices"
	"testing"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

func TestCaptureArgs(t *testing.T) {
	def := &fwconfig.Instance{Name: "main", Default: true, Interfaces: []fwconfig.Interface{{Name: "lan"}}}
	other := &fwconfig.Instance{Name: "dmz", Interfaces: []fwconfig.Interface{{Name: "lan"}}}

	req := agentapi.CaptureRequest{Interface: "lan", Filter: "-host 1.2.3.4", MaxPackets: 10, Snaplen: 1 << 20}
	argv, err := captureArgs(def, &req, 8443)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tcpdump", "-i", "lan", "-n", "-U", "-w", "-", "-s", "65535", "-c", "10",
		"--", "not tcp port 8443 and (-host 1.2.3.4)"}
	if !slices.Equal(argv, want) {
		t.Errorf("default instance:\n got %q\nwant %q", argv, want)
	}
	if req.MaxSeconds != agentapi.CaptureMaxSeconds {
		t.Errorf("max seconds not clamped: %d", req.MaxSeconds)
	}

	req = agentapi.CaptureRequest{Interface: "any"}
	argv, err = captureArgs(other, &req, 8443)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(argv, "--") {
		t.Errorf("no filter outside the default instance: %q", argv)
	}

	for _, bad := range []agentapi.CaptureRequest{
		{Interface: "eth9"},
		{Interface: "lan", Filter: "host 1.2.3.4\n"},
		{Interface: "lan", Filter: string(make([]byte, agentapi.CaptureMaxFilterLen+1))},
	} {
		if _, err := captureArgs(other, &bad, 0); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
