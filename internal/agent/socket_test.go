// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/abundo/portitor/internal/agentclient"
)

func TestLocalSocket(t *testing.T) {
	a, _ := testAgent(t)
	path := a.SocketPath()
	ln, err := listenSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: localHandler(a.routes())}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", st, err)
	}
	c := agentclient.NewLocal(path)
	if _, err := c.Neighbours(context.Background()); err != nil {
		t.Errorf("GET without token: %v", err)
	}
	if err := c.Confirm(context.Background(), 1); err == nil {
		t.Error("POST on the local socket succeeded")
	}
}
