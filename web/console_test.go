// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/abundo/portitor/internal/agent"
)

// consoleEnv runs portitor-web against a real dry-run agent whose console
// user is the test's own user (or consoleUser, when set).
func consoleEnv(t *testing.T, consoleUser string) (*testEnv, *httptest.Server) {
	t.Helper()
	env := newEnv(t)
	if consoleUser == "" {
		u, err := user.Current()
		if err != nil {
			t.Skip(err)
		}
		consoleUser = u.Username
	}
	dir := t.TempDir()
	token := strings.Repeat("t", 40)
	tokenFile := filepath.Join(dir, "token")
	_ = os.WriteFile(tokenFile, []byte(token), 0o600)
	cfgFile := filepath.Join(dir, "agent.yaml")
	_ = os.WriteFile(cfgFile, []byte("dry_run: true\nconsole_user: "+consoleUser+"\ntoken_file: "+tokenFile+"\npaths:\n  etc_dir: "+dir+"/etc\n  state_dir: "+dir+"/state\n  run_dir: "+dir+"/run\n  kea_data_dir: "+dir+"/kea\n"), 0o600)
	acfg, err := agent.LoadConfig(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	ag := agent.New(acfg)
	t.Cleanup(ag.Stop)
	ats := httptest.NewTLSServer(ag.Handler())
	t.Cleanup(ats.Close)
	sum := sha256.Sum256(ats.Certificate().Raw)
	if rec := env.do("PUT", "/api/settings", map[string]any{
		"agent_url": ats.URL, "agent_token": token, "agent_fingerprint": hex.EncodeToString(sum[:]),
	}); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body)
	}
	ws := httptest.NewServer(env.e)
	t.Cleanup(ws.Close)
	return env, ws
}

func dialConsole(ctx context.Context, env *testEnv, url, origin string) (*websocket.Conn, *http.Response, error) {
	h := http.Header{"Cookie": {env.cookie.String()}}
	if origin != "" {
		h.Set("Origin", origin)
	}
	return websocket.Dial(ctx, url+"/api/agent/console", &websocket.DialOptions{HTTPHeader: h})
}

func TestConsoleThroughWeb(t *testing.T) {
	env, ws := consoleEnv(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, _, err := dialConsole(ctx, env, ws.URL, ws.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_ = conn.Write(ctx, websocket.MessageText, []byte(`{"cols":100,"rows":30}`))
	_ = conn.Write(ctx, websocket.MessageBinary, []byte("echo PORTITOR-$((6*7)); stty size; exit\n"))
	var out strings.Builder
	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				break
			}
			if strings.Contains(err.Error(), "no login shell") {
				t.Skip(err)
			}
			t.Fatalf("read: %v (output %q)", err, out.String())
		}
		out.Write(data)
	}
	for _, want := range []string{"PORTITOR-42", "30 100"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q: %q", want, out.String())
		}
	}
}

func TestConsoleAgentErrorIsCloseReason(t *testing.T) {
	env, ws := consoleEnv(t, agent.ConsoleDisabled)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := dialConsole(ctx, env, ws.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, _, err = conn.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.StatusInternalError || !strings.Contains(ce.Reason, "disabled") {
		t.Fatalf("got %v, want a close with the agent's error", err)
	}
}

func TestConsoleRefusesOtherOrigin(t *testing.T) {
	env, ws := consoleEnv(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, resp, err := dialConsole(ctx, env, ws.URL, "https://evil.example")
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin console: err %v, resp %v", err, resp)
	}
}

func TestConsoleRequiresLogin(t *testing.T) {
	env, ws := consoleEnv(t, "")
	env.cookie = &http.Cookie{Name: cookieName, Value: "bogus"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, resp, err := dialConsole(ctx, env, ws.URL, "")
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("console without login: err %v, resp %v", err, resp)
	}
}
