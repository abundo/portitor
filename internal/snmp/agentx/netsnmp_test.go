// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agentx

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNetSNMP runs the session against net-snmp's snmpd as the master and
// reads it with snmpwalk, snmpbulkwalk and snmpget. Opt-in, as it starts
// snmpd: PORTITOR_SNMPD_TEST=1 go test -run NetSNMP ./internal/snmp/agentx/
func TestNetSNMP(t *testing.T) {
	if os.Getenv("PORTITOR_SNMPD_TEST") == "" {
		t.Skip("PORTITOR_SNMPD_TEST=1 runs it, with snmpd and snmpwalk installed")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "agentx")
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	conf := filepath.Join(dir, "snmpd.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf("agentAddress udp:127.0.0.1:%d\nmaster agentx\nagentXSocket unix:%s\nagentXTimeout 5\nrocommunity test 127.0.0.1\n", port, sock)), 0o600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	snmpd := exec.CommandContext(ctx, "snmpd", "-f", "-Lf", filepath.Join(dir, "snmpd.log"), "-C", "-c", conf)
	snmpd.Env = append(os.Environ(), "SNMP_PERSISTENT_DIR="+dir)
	if err := snmpd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		snmpd.Wait()
	}()

	base := OID{1, 3, 6, 1, 4, 1, 8072, 9999, 9999, 1}
	data := table{
		{base.Append(1, 1, 0), Value{OctetString, []byte("fw1")}},
		{base.Append(1, 2, 0), Value{Counter64, uint64(1) << 40}},
		{base.Append(1, 3, 0), Value{Gauge32, uint32(42)}},
		{base.Append(2, 1, 2, 4, 'm', 'a', 'i', 'n'), Value{Integer, int64(-3)}},
		{base.Append(2, 1, 2, 4, 'l', 'a', 'b', '1'), Value{Integer, int64(1)}},
	}
	// The table is sorted as a walk visits it.
	data[3], data[4] = data[4], data[3]
	s := &Session{Path: sock, Subtree: base, Name: "test", Handler: data, Retry: 200 * time.Millisecond}
	go s.Run(ctx)
	for i := 0; i < 50 && !s.Connected(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if !s.Connected() {
		log, _ := os.ReadFile(filepath.Join(dir, "snmpd.log"))
		t.Fatalf("not registered with snmpd:\n%s", log)
	}
	run := func(tool string, args ...string) string {
		t.Helper()
		out, err := exec.Command(tool, append([]string{"-v2c", "-c", "test", "-On", fmt.Sprintf("127.0.0.1:%d", port)}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", tool, err, out)
		}
		return string(out)
	}
	walk := run("snmpwalk", base.String())
	for _, want := range []string{
		".1.3.6.1.4.1.8072.9999.9999.1.1.1.0 = STRING: \"fw1\"",
		".1.3.6.1.4.1.8072.9999.9999.1.1.2.0 = Counter64: 1099511627776",
		".1.3.6.1.4.1.8072.9999.9999.1.1.3.0 = Gauge32: 42",
		".1.3.6.1.4.1.8072.9999.9999.1.2.1.2.4.108.97.98.49 = INTEGER: 1",
		".1.3.6.1.4.1.8072.9999.9999.1.2.1.2.4.109.97.105.110 = INTEGER: -3",
	} {
		if !strings.Contains(walk, want) {
			t.Errorf("snmpwalk lacks %q:\n%s", want, walk)
		}
	}
	if bulk := run("snmpbulkwalk", base.String()); bulk != walk {
		t.Errorf("snmpbulkwalk differs:\n%s\nsnmpwalk:\n%s", bulk, walk)
	}
	if get := run("snmpget", base.Append(1, 9, 0).String()); !strings.Contains(get, "No Such Instance") {
		t.Errorf("snmpget of nothing: %s", get)
	}
}
