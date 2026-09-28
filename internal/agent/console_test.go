// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/abundo/portitor/internal/agentapi"
)

func TestLoginShell(t *testing.T) {
	passwd := filepath.Join(t.TempDir(), "passwd")
	data := "root:x:0:0:root:/root:/bin/bash\n" +
		"portitor:x:1000:1000::/home/portitor:/bin/sh\n" +
		"svc:x:999:999::/nonexistent:/usr/sbin/nologin\n" +
		"empty:x:998:998::/:\n"
	if err := os.WriteFile(passwd, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, want, err string }{
		{"portitor", "/bin/sh", ""},
		{"empty", "/bin/sh", ""},
		{"svc", "", "no login shell"},
		{"nobody", "", "not in"},
	} {
		got, err := loginShell(passwd, tc.name)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

func TestConsoleDisabled(t *testing.T) {
	a, h := testAgent(t)
	a.cfg.ConsoleUser = ConsoleDisabled
	if rec := call(t, h, http.MethodGet, "/v1/console", testToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
}

func TestConsoleUnauthorized(t *testing.T) {
	_, h := testAgent(t)
	if rec := call(t, h, http.MethodGet, "/v1/console", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

// TestConsoleSession runs a real shell as the test's own user (dry run).
func TestConsoleSession(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	if _, err := loginShell("/etc/passwd", u.Username); err != nil {
		t.Skip(err)
	}
	a, h := testAgent(t)
	a.cfg.ConsoleUser = u.Username
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, srv.URL+"/v1/console", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + testToken}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	resize, _ := json.Marshal(agentapi.ConsoleResize{Cols: 120, Rows: 40})
	if err := conn.Write(ctx, websocket.MessageText, resize); err != nil {
		t.Fatal(err)
	}
	if err := conn.Write(ctx, websocket.MessageBinary, []byte("echo PORTITOR-$((6*7)); stty size; exit\n")); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
				t.Fatalf("read: %v (output %q)", err, out.String())
			}
			break
		}
		out.Write(data)
	}
	for _, want := range []string{"PORTITOR-42", "40 120"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q: %q", want, out.String())
		}
	}
}
