// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestEarly(t *testing.T) {
	lockout := &AntiLockout{Port: 8443, SSHPort: 22, ConfigPort: 8444, AllowFrom: []string{"192.168.1.0/24", "2001:db8::/64"}}
	for _, tc := range []struct {
		name    string
		lockout *AntiLockout
		want    []string
		notWant []string
	}{
		{"lockout", lockout, []string{
			`ip saddr 192.168.1.0/24 tcp dport { 22, 8443, 8444 } accept`,
			`ip6 saddr 2001:db8::/64 tcp dport { 22, 8443, 8444 } accept`,
		}, nil},
		{"none", nil, nil, []string{"tcp dport"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := Early(tc.lockout)
			for _, w := range append(tc.want,
				"table inet portitor_early {",
				"type filter hook input priority filter; policy drop;",
				"type filter hook forward priority filter; policy drop;",
				"udp sport 67 udp dport 68 accept") {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("unexpected %q in\n%s", w, out)
				}
			}
			if strings.Contains(out, "hook output") {
				t.Errorf("output must stay open:\n%s", out)
			}
			nftCheck(t, out)
		})
	}
	nftCheck(t, EarlyDelete())
}

// nftCheck runs nft -c on the ruleset where nft runs in a user namespace.
func nftCheck(t *testing.T, ruleset string) {
	t.Helper()
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	if err := exec.Command("unshare", "-rn", "nft", "list", "ruleset").Run(); err != nil {
		return
	}
	path := filepath.Join(t.TempDir(), "rules.nft")
	if err := os.WriteFile(path, []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("unshare", "-rn", "nft", "-c", "-f", path).CombinedOutput(); err != nil {
		t.Errorf("nft -c failed: %v\n%s\n%s", err, out, ruleset)
	}
}
