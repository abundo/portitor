// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/internal/render"
)

const testToken = "0123456789abcdef0123456789abcdef"

func testAgent(t *testing.T, allowFrom ...string) (*Agent, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		DryRun:    true,
		AllowFrom: allowFrom,
		Paths: render.Paths{
			EtcDir:       filepath.Join(dir, "etc"),
			StateDir:     filepath.Join(dir, "state"),
			RunDir:       filepath.Join(dir, "run"),
			KeaDataDir:   filepath.Join(dir, "kea"),
			KeaSocketDir: filepath.Join(dir, "kea"),
			NftablesFile: filepath.Join(dir, "std", "nftables.d", "portitor.nft"),
			WireGuardDir: filepath.Join(dir, "std", "wireguard"),
			NamedConf:    filepath.Join(dir, "std", "bind", "named.conf"),
			KeaConfDir:   filepath.Join(dir, "std", "kea"),
			RadvdConf:    filepath.Join(dir, "std", "radvd.conf"),
			FRRDir:       filepath.Join(dir, "std", "frr"),
			FRRRunDir:    filepath.Join(dir, "run", "frr"),
			FRRStateDir:  filepath.Join(dir, "state", "frr"),
		},
		token: testToken,
	}
	cfg.applyDefaults()
	a := New(cfg)
	t.Cleanup(a.Stop)
	return a, a.Handler()
}

func call(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.RemoteAddr = "192.168.1.50:40000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuth(t *testing.T) {
	_, h := testAgent(t)
	if rec := call(t, h, "GET", "/v1/status", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", rec.Code)
	}
	if rec := call(t, h, "GET", "/v1/status", "wrong", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", rec.Code)
	}
	if rec := call(t, h, "GET", "/v1/status", testToken, nil); rec.Code != http.StatusOK {
		t.Errorf("good token: %d", rec.Code)
	}
	_, h2 := testAgent(t, "10.0.0.0/8")
	if rec := call(t, h2, "GET", "/v1/status", testToken, nil); rec.Code != http.StatusForbidden {
		t.Errorf("outside allow_from: %d", rec.Code)
	}
}

func TestApplyRejectsInvalid(t *testing.T) {
	_, h := testAgent(t)
	doc := fwconfig.SampleDocument()
	doc.Instances[0].Rules[0].InInterfaces = []string{"nope"}
	rec := call(t, h, "POST", "/v1/apply", testToken, agentapi.ApplyRequest{Document: doc})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `unknown interface or interface zone`) {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestApplyConfirmAndRollback(t *testing.T) {
	a, h := testAgent(t)
	first := fwconfig.SampleDocument()
	first.Generation = 1

	rec := call(t, h, "POST", "/v1/apply", testToken, agentapi.ApplyRequest{Document: first})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply 1: %d %s", rec.Code, rec.Body)
	}
	var res agentapi.ApplyResult
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	joined := strings.Join(res.Log, "\n")
	for _, want := range []string{"(dry-run) ip netns add fw-guest", "(dry-run) ip link add lk-guest type veth peer name lk-main netns fw-guest", "nftables.nft"} {
		if !strings.Contains(joined, want) {
			t.Errorf("log lacks %q:\n%s", want, joined)
		}
	}

	// Second apply with a confirm window that we let expire.
	second := fwconfig.SampleDocument()
	second.Generation = 2
	rec = call(t, h, "POST", "/v1/apply", testToken, agentapi.ApplyRequest{Document: second, ConfirmTimeoutSeconds: 1})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply 2: %d %s", rec.Code, rec.Body)
	}
	if st := a.Status(t.Context()); st.Pending == nil || st.Generation != 2 {
		t.Fatalf("expected pending generation 2: %+v", st)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := a.Status(t.Context()); st.Pending == nil {
			if st.Generation != 1 {
				t.Fatalf("rolled back to %d, want 1", st.Generation)
			}
			goto confirmed
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no rollback after the confirm timeout")

confirmed:
	// Third apply, confirmed in time.
	third := fwconfig.SampleDocument()
	third.Generation = 3
	call(t, h, "POST", "/v1/apply", testToken, agentapi.ApplyRequest{Document: third, ConfirmTimeoutSeconds: 60})
	if rec := call(t, h, "POST", "/v1/confirm", testToken, agentapi.ConfirmRequest{Generation: 2}); rec.Code != http.StatusConflict {
		t.Errorf("confirming the wrong generation: %d", rec.Code)
	}
	if rec := call(t, h, "POST", "/v1/confirm", testToken, agentapi.ConfirmRequest{Generation: 3}); rec.Code != http.StatusOK {
		t.Errorf("confirm: %d %s", rec.Code, rec.Body)
	}
	if st := a.Status(t.Context()); st.Pending != nil || st.Generation != 3 {
		t.Errorf("after confirm: %+v", st)
	}
}

func TestRenderPreview(t *testing.T) {
	_, h := testAgent(t)
	rec := call(t, h, "POST", "/v1/render", testToken, agentapi.RenderRequest{Document: fwconfig.SampleDocument()})
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "YEocP0e2o1WT5GlvBvQzVF7EeR6z9aCk8ZdZ5oPr1Wk=") {
		t.Error("preview leaks the WireGuard private key")
	}
}
