// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentclient"
)

// handleAgentConsole connects the browser's WebSocket to the agent's
// console (a shell on the firewall) and passes messages through both ways.
// Errors after the upgrade reach the browser as the close reason, which is
// all a browser WebSocket can see.
func (s *Server) handleAgentConsole(c *echo.Context) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	w, r := c.Response(), c.Request()
	opts := &websocket.AcceptOptions{}
	if s.cfg.Dev {
		// The Vite dev server proxies with its own origin.
		opts.OriginPatterns = []string{"localhost:*", "127.0.0.1:*"}
	}
	// The server's read timeout is for requests, not a session.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	browser, err := websocket.Accept(w, r, opts)
	if err != nil {
		return nil // Accept has answered
	}
	defer browser.CloseNow()
	browser.SetReadLimit(1 << 20)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	agent, err := a.Console(dialCtx)
	dialCancel()
	if err != nil {
		msg := err.Error()
		var ae *agentclient.Error
		if errors.As(err, &ae) {
			msg = ae.Message
		}
		browser.Close(websocket.StatusInternalError, closeReason(msg))
		return nil
	}
	defer agent.CloseNow()
	agent.SetReadLimit(1 << 20)

	user := currentUser(c)
	slog.Info("console opened", "user", user.Username, "remote", c.RealIP())
	defer slog.Info("console closed", "user", user.Username, "remote", c.RealIP())

	fromBrowser := make(chan error, 1)
	fromAgent := make(chan error, 1)
	go func() { fromBrowser <- pump(ctx, agent, browser) }()
	go func() { fromAgent <- pump(ctx, browser, agent) }()
	select {
	case <-fromBrowser:
		agent.Close(websocket.StatusNormalClosure, "")
	case err := <-fromAgent:
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			browser.Close(ce.Code, ce.Reason)
		} else {
			browser.Close(websocket.StatusInternalError, "lost the connection to the agent")
		}
	}
	return nil
}

// pump copies messages from src to dst until either fails.
func pump(ctx context.Context, dst, src *websocket.Conn) error {
	for {
		typ, data, err := src.Read(ctx)
		if err != nil {
			return err
		}
		if err := dst.Write(ctx, typ, data); err != nil {
			return err
		}
	}
}

// closeReason fits a WebSocket close reason (at most 123 bytes).
func closeReason(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
