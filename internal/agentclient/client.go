// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package agentclient is portitor-web's client for the portitor-agent API.
package agentclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Error is a non-2xx answer from the agent.
type Error struct {
	Status   int
	Message  string
	Problems []string
	// Result is set when an apply failed after changing things (it
	// carries the log and whether the agent rolled back).
	Result *agentapi.ApplyResult
}

func (e *Error) Error() string {
	return fmt.Sprintf("agent: %s (HTTP %d)", e.Message, e.Status)
}

// New returns a client. With a fingerprint, the agent's certificate is
// pinned (SHA-256 of the leaf certificate, hex, colons allowed) and CA
// validation is skipped; that is how the agent's self-signed certificate
// from `portitor-agent init` is trusted.
func New(baseURL, token, fingerprint string) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("agent URL is not configured (Settings)")
	}
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, errors.New("agent URL must be https://")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	fp := strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
	if fp != "" {
		want, err := hex.DecodeString(fp)
		if err != nil || len(want) != sha256.Size {
			return nil, errors.New("agent fingerprint must be a SHA-256 hex string")
		}
		tlsCfg.InsecureSkipVerify = true // replaced by the pin check below
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("agent presented no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return fmt.Errorf("agent certificate fingerprint mismatch (got %s)", hex.EncodeToString(got[:]))
			}
			return nil
		}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http: &http.Client{
			Timeout:   5 * time.Minute,
			Transport: &http.Transport{TLSClientConfig: tlsCfg, ResponseHeaderTimeout: 5 * time.Minute},
		},
	}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("agent unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			agentapi.ErrorResponse
			Result *agentapi.ApplyResult `json:"result"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &Error{Status: resp.StatusCode, Message: e.Error, Problems: e.Problems, Result: e.Result}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) Status(ctx context.Context) (*agentapi.Status, error) {
	var st agentapi.Status
	return &st, c.do(ctx, http.MethodGet, "/v1/status", nil, &st)
}

func (c *Client) Leases(ctx context.Context) (*agentapi.LeasesResponse, error) {
	var l agentapi.LeasesResponse
	return &l, c.do(ctx, http.MethodGet, "/v1/leases", nil, &l)
}

// RuleCounters returns the traffic counted per rule since the last apply.
func (c *Client) RuleCounters(ctx context.Context) (*agentapi.RuleCountersResponse, error) {
	var r agentapi.RuleCountersResponse
	return &r, c.do(ctx, http.MethodGet, "/v1/rule-counters", nil, &r)
}

// Logs returns the agent's log records with an id above after.
func (c *Client) Logs(ctx context.Context, after int64) (*agentapi.LogsResponse, error) {
	var l agentapi.LogsResponse
	return &l, c.do(ctx, http.MethodGet, "/v1/logs?after="+strconv.FormatInt(after, 10), nil, &l)
}

// PacketLog returns the packets the rulesets logged with an id above after.
func (c *Client) PacketLog(ctx context.Context, after int64) (*agentapi.PacketLogResponse, error) {
	var l agentapi.PacketLogResponse
	return &l, c.do(ctx, http.MethodGet, "/v1/packet-log?after="+strconv.FormatInt(after, 10), nil, &l)
}

func (c *Client) Render(ctx context.Context, doc fwconfig.Document) (*agentapi.RenderResult, error) {
	var r agentapi.RenderResult
	return &r, c.do(ctx, http.MethodPost, "/v1/render", agentapi.RenderRequest{Document: doc}, &r)
}

func (c *Client) Apply(ctx context.Context, doc fwconfig.Document, confirmTimeout int) (*agentapi.ApplyResult, error) {
	var r agentapi.ApplyResult
	return &r, c.do(ctx, http.MethodPost, "/v1/apply", agentapi.ApplyRequest{Document: doc, ConfirmTimeoutSeconds: confirmTimeout}, &r)
}

func (c *Client) Confirm(ctx context.Context, generation int64) error {
	return c.do(ctx, http.MethodPost, "/v1/confirm", agentapi.ConfirmRequest{Generation: generation}, nil)
}

func (c *Client) Rollback(ctx context.Context) (*agentapi.ApplyResult, error) {
	var r agentapi.ApplyResult
	return &r, c.do(ctx, http.MethodPost, "/v1/rollback", struct{}{}, &r)
}

// RunTask starts a task of the applied configuration now.
func (c *Client) RunTask(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/tasks/run", agentapi.RunRequest{Name: name}, nil)
}

// RefreshIPList starts downloading an IP list of the applied
// configuration now.
func (c *Client) RefreshIPList(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/v1/iplists/refresh", agentapi.RunRequest{Name: name}, nil)
}

// System returns the operating system, its updates and the update jobs.
func (c *Client) System(ctx context.Context) (*agentapi.SystemStatus, error) {
	var st agentapi.SystemStatus
	return &st, c.do(ctx, http.MethodGet, "/v1/system", nil, &st)
}

// StartSystemJob starts an update job (agentapi.JobCheck, ...).
func (c *Client) StartSystemJob(ctx context.Context, req agentapi.SystemJobRequest) error {
	return c.do(ctx, http.MethodPost, "/v1/system/jobs", req, nil)
}

// Reboot restarts the firewall.
func (c *Client) Reboot(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/system/reboot", struct{}{}, nil)
}

// Console opens the agent's console WebSocket (agentapi.ConsoleResize).
func (c *Client) Console(ctx context.Context) (*websocket.Conn, error) {
	conn, resp, err := websocket.Dial(ctx, c.baseURL+"/v1/console", &websocket.DialOptions{
		HTTPClient: c.http,
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.token}},
	})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			var e agentapi.ErrorResponse
			if resp.Body != nil {
				data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
				_ = json.Unmarshal(data, &e)
			}
			if e.Error == "" {
				e.Error = http.StatusText(resp.StatusCode)
			}
			return nil, &Error{Status: resp.StatusCode, Message: e.Error}
		}
		return nil, fmt.Errorf("agent unreachable: %w", err)
	}
	return conn, nil
}
