// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// parseRunner answers the import's unshare with out or err.
type parseRunner struct {
	Runner
	out   string
	err   error
	stdin string
}

func (r *parseRunner) RunInput(_ context.Context, _ string, stdin []byte, name string, _ ...string) ([]byte, error) {
	if name != "unshare" {
		return nil, errors.New("unexpected " + name)
	}
	r.stdin = string(stdin)
	return []byte(r.out), r.err
}

func TestParseNftables(t *testing.T) {
	r := &parseRunner{out: `{"nftables": []}` + "\n\n" + nftSplit + "\ntable inet filter { # handle 1\n}\n"}
	a := &Agent{run: r}
	res, err := a.ParseNftables(context.Background(), "table inet filter {}")
	if err != nil || string(res.JSON) != `{"nftables": []}` || !strings.HasPrefix(res.Text, "table inet filter") {
		t.Fatalf("parse: %v %+v", err, res)
	}
	if r.stdin != "table inet filter {}" {
		t.Errorf("stdin %q", r.stdin)
	}

	if _, err := a.ParseNftables(context.Background(), "flush ruleset\n  include \"/etc/shadow\"\n"); err == nil || !strings.Contains(err.Error(), "include") {
		t.Errorf("include: %v", err)
	}
	if _, err := a.ParseNftables(context.Background(), strings.Repeat("#", maxNftablesImport+1)); err == nil {
		t.Error("an oversized file was read")
	}

	r.err = errors.New("unshare --net -- sh -c nft -f -: exit status 1: /dev/stdin:1:44-44: Error: syntax error")
	if _, err := a.ParseNftables(context.Background(), "x"); err == nil || err.Error() != "line 1:44-44: Error: syntax error" {
		t.Errorf("nft error: %v", err)
	}
}
