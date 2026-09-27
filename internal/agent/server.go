// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

const maxBody = 8 << 20

// maxConfirmTimeout caps how long a change may wait for confirmation.
const maxConfirmTimeout = 30 * time.Minute

// Handler returns the management API.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, a.Status(r.Context()))
	})
	mux.HandleFunc("GET /v1/leases", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, agentapi.LeasesResponse{Client: a.dhcp.Leases(), Server: a.ServerLeases()})
	})
	mux.HandleFunc("POST /v1/render", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.RenderRequest
		if !decode(w, r, &req) {
			return
		}
		res, err := a.Render(req.Document)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /v1/apply", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.ApplyRequest
		if !decode(w, r, &req) {
			return
		}
		timeout := time.Duration(req.ConfirmTimeoutSeconds) * time.Second
		if timeout < 0 || timeout > maxConfirmTimeout {
			writeError(w, http.StatusBadRequest, errors.New("confirm_timeout_seconds out of range"))
			return
		}
		// Apply must finish even if the client goes away (its own rules
		// may be what cut the connection).
		res, err := a.Apply(context.WithoutCancel(r.Context()), req.Document, timeout)
		if err != nil {
			status := http.StatusInternalServerError
			var ve *fwconfig.ValidationError
			if errors.As(err, &ve) {
				status = http.StatusUnprocessableEntity
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(struct {
				agentapi.ErrorResponse
				Result *agentapi.ApplyResult `json:"result,omitempty"`
			}{errorBody(err), res})
			return
		}
		writeJSONResponse(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /v1/confirm", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.ConfirmRequest
		if !decode(w, r, &req) {
			return
		}
		if err := a.Confirm(req.Generation); err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, map[string]any{"confirmed": req.Generation})
	})
	mux.HandleFunc("POST /v1/rollback", func(w http.ResponseWriter, r *http.Request) {
		res, err := a.Rollback(context.WithoutCancel(r.Context()))
		if err != nil {
			writeError(w, http.StatusConflict, err)
			return
		}
		writeJSONResponse(w, http.StatusOK, res)
	})
	return a.authMiddleware(mux)
}

func (a *Agent) authMiddleware(next http.Handler) http.Handler {
	var allow []netip.Prefix
	for _, s := range a.cfg.AllowFrom {
		if p, err := netip.ParsePrefix(s); err == nil {
			allow = append(allow, p.Masked())
		}
	}
	want := []byte("Bearer " + a.cfg.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allow) > 0 {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			addr, err := netip.ParseAddr(host)
			ok := false
			if err == nil {
				addr = addr.Unmap()
				for _, p := range allow {
					if p.Contains(addr) {
						ok = true
						break
					}
				}
			}
			if !ok {
				slog.Warn("api: client not in allow_from", "remote", r.RemoteAddr)
				writeError(w, http.StatusForbidden, errors.New("forbidden"))
				return
			}
		}
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			slog.Warn("api: bad token", "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

// Serve runs the API until ctx is cancelled.
func (a *Agent) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              a.cfg.Listen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Apply can take a while (dnsmgr2, service restarts).
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  2 * time.Minute,
		TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS13},
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("portitor-agent API listening", "addr", a.cfg.Listen, "tls", a.cfg.TLSCert != "", "dry_run", a.cfg.DryRun)
		if a.cfg.TLSCert != "" {
			errc <- srv.ListenAndServeTLS(a.cfg.TLSCert, a.cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return false
	}
	return true
}

func errorBody(err error) agentapi.ErrorResponse {
	body := agentapi.ErrorResponse{Error: err.Error()}
	var ve *fwconfig.ValidationError
	if errors.As(err, &ve) {
		body.Problems = ve.Problems
	}
	return body
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSONResponse(w, status, errorBody(err))
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
