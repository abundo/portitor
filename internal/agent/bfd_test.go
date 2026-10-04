// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import "testing"

func TestParseBFDPeers(t *testing.T) {
	peers, err := parseBFDPeers([]byte(`[
 {"multihop":false,"peer":"192.0.2.2","local":"192.0.2.1","vrf":"default","interface":"eth1","id":1,"remote-id":7,
  "passive-mode":false,"profile":"if-eth1","status":"up","uptime":42,"diagnostic":"ok","remote-diagnostic":"ok",
  "receive-interval":300,"transmit-interval":300,"detect-multiplier":3,
  "remote-receive-interval":200,"remote-transmit-interval":200,"remote-detect-multiplier":5},
 {"multihop":false,"peer":"192.0.2.9","interface":"eth0","status":"down","downtime":10,"diagnostic":"control detection time expired"}
]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 || peers[0].Interface != "eth0" || peers[0].Status != "down" || peers[0].Downtime != 10 {
		t.Fatalf("peers: %+v", peers)
	}
	if p := peers[1]; p.Peer != "192.0.2.2" || p.Profile != "if-eth1" || p.Uptime != 42 || p.RemoteDetectMultiplier != 5 || p.RemoteReceiveInterval != 200 {
		t.Errorf("peer: %+v", p)
	}
}
