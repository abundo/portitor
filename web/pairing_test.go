// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"
)

func testSecondaryInfo() SecondaryInfo {
	return SecondaryInfo{Name: "fw1b", Address: "192.0.2.3", AgentPort: 8443, ConfigPort: 443,
		Token: strings.Repeat("t", 40), AgentFingerprint: strings.Repeat("ab", 32), ConfigFingerprint: strings.Repeat("cd", 32)}
}

// A primary with its two links and no secondary gets one from the
// information of secondary-info, and the pair is committed.
func TestAddSecondary(t *testing.T) {
	env, agents, _ := twoFirewalls(t)
	env.mustCfg("DELETE", "instance=shop", nil)
	env.do("PUT", "/api/firewalls/1", map[string]any{"name": "firewall", "agent_url": "https://192.0.2.1:8443",
		"agent_fingerprint": strings.Repeat("ab", 32)})
	ctx := t.Context()
	// The secondary is the second firewall.
	secID := uint(2)
	agents[secID] = &fleetAgent{}

	// Without the links: nothing to pair.
	if err := AddSecondary(ctx, env.srv, testSecondaryInfo(), false); err == nil || !strings.Contains(err.Error(), "HA link") {
		t.Fatalf("no links: %v", err)
	}
	addHALinks(t, env)
	env.mustCfg("PATCH", "instance=main/interface=mgmt0", map[string]any{"peer-addresses": []string{}})

	// An address outside the management network, and the primary's own.
	for _, a := range []string{"198.51.100.3", "192.0.2.1", "nonsense", "2001:db8::3"} {
		i := testSecondaryInfo()
		i.Address = a
		if err := AddSecondary(ctx, env.srv, i, false); err == nil {
			t.Errorf("address %s accepted", a)
		}
	}
	bad := testSecondaryInfo()
	bad.ConfigFingerprint = "abc"
	if err := AddSecondary(ctx, env.srv, bad, false); err == nil {
		t.Error("a short fingerprint accepted")
	}

	if err := AddSecondary(ctx, env.srv, testSecondaryInfo(), true); err != nil {
		t.Fatal(err)
	}
	sec, _ := env.srv.rec.Firewall(secID)
	if sec == nil || sec.Name != "fw1b" || sec.HAPrimaryID == nil || *sec.HAPrimaryID != 1 ||
		sec.AgentURL != "https://192.0.2.3:8443" || sec.ConfigURL != "https://192.0.2.3:443" ||
		sec.AgentToken != strings.Repeat("t", 40) || sec.AgentFingerprint != strings.Repeat("ab", 32) {
		t.Fatalf("secondary: %+v", sec)
	}
	prim, _ := env.srv.rec.Firewall(1)
	if prim.HAWitness != "external" || prim.HAWitnessSecret == "" {
		t.Errorf("witness: %q", prim.HAWitness)
	}
	code, body := env.srv.ConsoleRequest(ctx, "GET", "/api/config/candidate/instance=main/interface=mgmt0", nil)
	if code != http.StatusOK || !strings.Contains(string(body), "192.0.2.3/24") || !strings.Contains(string(body), "peer-addresses") {
		t.Errorf("peer addresses: %d %s", code, body)
	}
	if agents[1] == nil || len(agents[1].applied) == 0 {
		t.Error("the pair was not committed")
	}
	if str, err := env.srv.witnessString(prim); err != nil || !strings.HasPrefix(str, WitnessPrefix) {
		t.Errorf("witness string: %q %v", str, err)
	}
	// A second secondary is refused.
	i := testSecondaryInfo()
	i.Name, i.Address = "fw1c", "192.0.2.4"
	if err := AddSecondary(ctx, env.srv, i, false); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("second secondary: %v", err)
	}
}

// A host with one firewall prints its information, a paired one doesn't.
func TestReadSecondaryInfo(t *testing.T) {
	env := newEnv(t)
	env.srv.cfg.TLSCert = ""
	if _, err := ReadSecondaryInfo(env.srv, env.srv.cfg); err == nil {
		t.Error("a host without an agent or TLS gave its information")
	}
}
