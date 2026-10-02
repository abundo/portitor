// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/abundo/portitor/internal/agentapi"
)

func TestConnections(t *testing.T) {
	flow := func(bytes uint64) *netlink.ConntrackFlow {
		return &netlink.ConntrackFlow{
			FamilyType: unix.AF_INET,
			Forward:    netlink.IPTuple{Protocol: unix.IPPROTO_TCP, SrcIP: net.IPv4(10, 0, 0, 2), DstIP: net.IPv4(192, 0, 2, 1), SrcPort: 40000, DstPort: 443, Bytes: bytes},
			Reverse:    netlink.IPTuple{Protocol: unix.IPPROTO_TCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(198, 51, 100, 1), SrcPort: 443, DstPort: 40000},
			Mark:       7,
			ProtoInfo:  &netlink.ProtoInfoTCP{State: 3},
		}
	}
	total, out := connections([]*netlink.ConntrackFlow{flow(1), flow(30), flow(20)}, 2)
	if total != 3 || len(out) != 2 || out[0].Bytes != 30 || out[1].Bytes != 20 {
		t.Fatalf("%d %+v", total, out)
	}
	c := out[0]
	if c.Protocol != "tcp" || c.State != "ESTABLISHED" || c.Src != "10.0.0.2" || c.ReplyDst != "198.51.100.1" || c.DstPort != 443 || c.Mark != 7 || c.Family != "ipv4" {
		t.Errorf("%+v", c)
	}

	req := agentapi.ConnectionsRequest{IntervalMs: 10, Max: 1 << 20}
	clampConnections(&req)
	if req.IntervalMs != agentapi.ConnectionsMinIntervalMs || req.Max != agentapi.ConnectionsMaxEntries {
		t.Errorf("%+v", req)
	}
}
