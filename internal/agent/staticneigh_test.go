// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func TestPlanStaticNeighbours(t *testing.T) {
	have := append(parseIPNeigh([]byte(`[
		{"dst":"192.168.1.10","dev":"eth1","lladdr":"02:00:00:00:00:10","state":["PERMANENT"]},
		{"dst":"192.168.1.11","dev":"eth1","lladdr":"02:00:00:00:00:11","state":["PERMANENT"]},
		{"dst":"192.168.1.12","dev":"eth1","lladdr":"02:00:00:00:00:12","state":["PERMANENT"]},
		{"dst":"192.168.1.99","dev":"eth1","lladdr":"02:00:00:00:00:99","state":["PERMANENT"]}]`), false),
		parseIPNeigh([]byte(`[{"dst":"fd00:1::5","dev":"eth1","lladdr":"02:00:00:00:00:05","state":["PERMANENT"]}]`), true)...)
	want := []fwconfig.StaticNeighbour{
		{Interface: "eth1", Address: "192.168.1.10", MAC: "02:00:00:00:00:10"}, // there
		{Interface: "eth1", Address: "192.168.1.11", MAC: "02-00-00-00-00-AA"}, // other MAC
		{Interface: "eth1", Address: "fd00:1:0::5", MAC: "02:00:00:00:00:05"},  // there
		{Interface: "eth2", Address: "fd00:2::1", MAC: "02:00:00:00:00:21"},    // new
	}
	applied := []fwconfig.StaticNeighbour{
		{Interface: "eth1", Address: "192.168.1.12", MAC: "02:00:00:00:00:12"}, // no longer wanted
		{Interface: "eth1", Address: "192.168.1.13", MAC: "02:00:00:00:00:13"}, // gone already
	}
	// 192.168.1.99 isn't the agent's: left alone.
	equal(t, planStaticNeighbours("", want, have, applied),
		"ip neigh del 192.168.1.12 dev eth1",
		"ip neigh replace 192.168.1.11 lladdr 02:00:00:00:00:aa dev eth1 nud permanent",
		"ip neigh replace fd00:2::1 lladdr 02:00:00:00:00:21 dev eth2 nud permanent")
}
