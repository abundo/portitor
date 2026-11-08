// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/abundo/portitor/internal/snmp/agentx"
)

// portitor-config's subagent registers the MIB's base with the master and
// answers a walk of the state from the (dry-run) agent.
func TestSNMPAgentX(t *testing.T) {
	env, _ := consoleEnv(t, "")
	sock := filepath.Join(t.TempDir(), "master")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	env.srv.cfg.SNMP.AgentX = sock
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go env.srv.runSNMP(ctx)

	m, err := agentx.Accept(l)
	if err != nil {
		t.Fatal(err)
	}
	mib, err := env.srv.SNMPMIB()
	if err != nil {
		t.Fatal(err)
	}
	if m.Subtree.Compare(mib.Base) != 0 {
		t.Fatalf("registered %s, want %s", m.Subtree, mib.Base)
	}
	var dryRun agentx.OID
	for _, c := range mib.Groups[0].Scalars {
		if c.Name == "ptSystemStateDryRun" {
			dryRun = mib.Base.Append(mib.Groups[0].Num, c.Num, 0)
		}
	}
	vbs, err := m.Get(dryRun)
	if err != nil || len(vbs) != 1 || vbs[0].Value.Type != agentx.Integer || vbs[0].Value.Data != int64(1) {
		t.Fatalf("dry-run: %+v %v", vbs, err)
	}
	walk, err := m.Walk(mib.Base)
	if err != nil || len(walk) < 5 {
		t.Fatalf("walk: %d objects, %v", len(walk), err)
	}
	t.Logf("%d objects, the first %s", len(walk), walk[0].Name)
}
