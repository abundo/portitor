// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestPlanNAT64(t *testing.T) {
	wk := &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix, Interfaces: []string{"eth1"}}
	pool := &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix, Pool4: []string{"192.0.2.0/28"}}

	equal(t, planNAT64("fw-guest", wk, nil, false),
		"modprobe jool",
		"fw-guest jool instance add portitor --netfilter --pool6 64:ff9b::/96",
	)
	// Applied and running: nothing, whatever the interfaces.
	equal(t, planNAT64("fw-guest", wk, &fwconfig.NAT64{Prefix: fwconfig.NAT64WellKnownPrefix}, true))
	// Applied, but gone (a reboot): made again.
	equal(t, planNAT64("", wk, wk, false),
		"modprobe jool",
		"jool instance add portitor --netfilter --pool6 64:ff9b::/96",
	)
	// Running as nobody knows: made again.
	equal(t, planNAT64("", pool, nil, true),
		"jool instance remove portitor",
		"modprobe jool",
		"jool instance add portitor --netfilter --pool6 64:ff9b::/96",
		"jool -i portitor pool4 add --tcp 192.0.2.0/28 1-65535",
		"jool -i portitor pool4 add --udp 192.0.2.0/28 1-65535",
		"jool -i portitor pool4 add --icmp 192.0.2.0/28 1-65535",
	)
	equal(t, planNAT64("", nil, wk, true), "jool instance remove portitor")
	equal(t, planNAT64("", nil, nil, false))
}
