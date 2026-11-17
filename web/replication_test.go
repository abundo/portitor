// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// The primary knows whether its secondary holds its configuration, from the
// replica's reports, and a commit waits for the copy.
func TestReplication(t *testing.T) {
	ctx := context.Background()
	prim, _, pair := haPairConfigured(t)
	sec := prim.firewall(pair)
	// No secondary's portitor-config known: nothing to tell.
	asHost(t, prim, 1, agentapi.HAPeerConfig{Node: fwconfig.HAPrimary})
	if st := prim.srv.replication(ctx); st != nil {
		t.Fatalf("replication without a secondary: %+v", st)
	}
	asHost(t, prim, 1, agentapi.HAPeerConfig{Node: fwconfig.HAPrimary, URL: "https://127.0.0.1:1", Secret: sec.HASecret})
	ts := httptest.NewTLSServer(prim.e)
	defer ts.Close()
	sum := sha256.Sum256(ts.Certificate().Raw)
	prim.commit()

	st := prim.srv.replication(ctx)
	if st == nil || st.Replicated || st.Reported != nil || !strings.Contains(st.warning(), "not reported") {
		t.Fatalf("before any copy: %+v %q", st, st.warning())
	}

	rep := newEnv(t)
	if err := rep.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	asHost(t, rep, 1, agentapi.HAPeerConfig{Node: fwconfig.HASecondary, URL: ts.URL, Fingerprint: hex.EncodeToString(sum[:]), Secret: sec.HASecret})
	copyAndReport := func() {
		err := rep.srv.copyPrimary(ctx)
		if err != nil {
			t.Fatalf("copy: %v", err)
		}
		rep.srv.reportCopy(ctx, err)
	}
	copyAndReport()
	if st := prim.srv.replication(ctx); st == nil || !st.Replicated || st.Copied == nil || st.warning() != "" {
		t.Fatalf("after the copy: %+v", st)
	}

	// A new commit is not on the secondary until it copies it.
	prim.commit()
	if st := prim.srv.awaitReplica(ctx, 10*time.Millisecond); st == nil || st.Replicated {
		t.Fatalf("a commit not copied: %+v", st)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		copyAndReport()
	}()
	if st := prim.srv.awaitReplica(ctx, 5*time.Second); st == nil || !st.Replicated {
		t.Fatalf("waiting for the copy: %+v", st)
	}

	// A failed copy is reported with its error.
	prim.commit()
	rep.srv.reportCopy(ctx, errors.New("disk full"))
	if st := prim.srv.replication(ctx); st == nil || st.Replicated || !strings.Contains(st.warning(), "disk full") {
		t.Fatalf("a failed copy: %+v", st)
	}
}
