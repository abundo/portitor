// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/abundo/portitor/internal/acme"
	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

const maxBody = 8 << 20

// maxConfirmTimeout caps how long a change may wait for confirmation.
const maxConfirmTimeout = 30 * time.Minute

// Handler returns the management API.
func (a *Agent) Handler() http.Handler {
	return a.authMiddleware(a.routes())
}

func (a *Agent) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, a.Status(r.Context()))
	})
	mux.HandleFunc("GET /v1/leases", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, agentapi.LeasesResponse{Client: clientLeases(a.dhcp.Leases(), a.dhcp6.Leases()), Server: a.ServerLeases()})
	})
	mux.HandleFunc("GET /v1/neighbours", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, a.Neighbours(r.Context()))
	})
	mux.HandleFunc("GET /v1/routing-table", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, a.RoutingTable(r.Context()))
	})
	mux.HandleFunc("GET /v1/rule-counters", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, a.RuleCounters(r.Context()))
	})
	mux.HandleFunc("GET /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		writeJSONResponse(w, http.StatusOK, agentapi.LogsResponse{Entries: Logs.After(after)})
	})
	mux.HandleFunc("GET /v1/packet-log", func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		writeJSONResponse(w, http.StatusOK, agentapi.PacketLogResponse{Entries: a.pkts.After(after)})
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
	mux.HandleFunc("POST /v1/tasks/run", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.RunRequest
		if decode(w, r, &req) {
			writeStarted(w, req.Name, a.tasks.RunNow(req.Name))
		}
	})
	mux.HandleFunc("POST /v1/iplists/refresh", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.RunRequest
		if decode(w, r, &req) {
			writeStarted(w, req.Name, a.RefreshIPList(req.Name))
		}
	})
	mux.HandleFunc("GET /v1/system", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, a.sys.Status(r.Context()))
	})
	mux.HandleFunc("POST /v1/system/jobs", func(w http.ResponseWriter, r *http.Request) {
		var req agentapi.SystemJobRequest
		if !decode(w, r, &req) {
			return
		}
		slog.Info("api: update job", "job", req.Job, "release", req.Release, "remote", r.RemoteAddr)
		err := a.sys.Start(r.Context(), req)
		var busy errBusy
		if err != nil && !errors.As(err, &busy) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeStarted(w, req.Job, err)
	})
	mux.HandleFunc("POST /v1/system/reboot", func(w http.ResponseWriter, r *http.Request) {
		slog.Warn("api: reboot requested", "remote", r.RemoteAddr)
		a.sys.Reboot()
		writeJSONResponse(w, http.StatusAccepted, map[string]any{"rebooting": true})
	})
	mux.HandleFunc("GET /v1/certificates/{instance}/{name}", a.handleCertificate)
	mux.HandleFunc("GET /v1/console", a.handleConsole)
	mux.HandleFunc("POST /v1/capture", a.handleCapture)
	mux.HandleFunc("POST /v1/trace", a.handleTrace)
	return mux
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
	errc := make(chan error, 2)
	if a.cfg.DryRun {
		// A dev agent runs unprivileged; the socket is for the firewall.
	} else if ln, err := listenSocket(a.SocketPath()); err != nil {
		slog.Warn("local socket not available", "err", err)
	} else {
		local := &http.Server{Handler: localHandler(a.routes()), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
		go func() { errc <- local.Serve(ln) }()
		defer local.Close()
	}
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

// SocketPath is the local API socket the portitor command talks to.
func (a *Agent) SocketPath() string {
	return filepath.Join(a.cfg.Paths.RunDir, SocketName)
}

// SocketName is the local socket's name in run_dir.
const SocketName = "agent.sock"

// listenSocket listens on a Unix socket only root can connect to: the
// file mode is the socket's authentication.
func listenSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// localHandler serves the API's GET routes, without the token: the
// socket's permissions already limit it to root. Changes go through
// portitor-web.
func localHandler(api http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, errors.New("the local socket is read-only"))
			return
		}
		api.ServeHTTP(w, r)
	})
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

// writeStarted answers a request to start a task or download: 202, or
// why it could not start.
func writeStarted(w http.ResponseWriter, name string, err error) {
	var nf errNotFound
	var busy errBusy
	switch {
	case errors.As(err, &nf):
		writeError(w, http.StatusNotFound, err)
	case errors.As(err, &busy):
		writeError(w, http.StatusConflict, err)
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
	default:
		writeJSONResponse(w, http.StatusAccepted, map[string]any{"started": name})
	}
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

// handleCertificate hands out a stored certificate and its key, for
// portitor-web's tls_certificate. Only a complete one (acme.Load).
func (a *Agent) handleCertificate(w http.ResponseWriter, r *http.Request) {
	inst, name := r.PathValue("instance"), r.PathValue("name")
	if !fwconfig.ValidInstanceName(inst) || !fwconfig.ValidItemName(name) {
		writeError(w, http.StatusBadRequest, errors.New("bad instance or certificate name"))
		return
	}
	dir := a.cfg.Paths.CertificateDir(inst, name)
	if acme.Load(dir) == nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("no certificate %s/%s yet", inst, name))
		return
	}
	chain, err := os.ReadFile(filepath.Join(dir, acme.FullChainFile))
	if err == nil {
		var key []byte
		if key, err = os.ReadFile(filepath.Join(dir, acme.PrivKeyFile)); err == nil {
			writeJSONResponse(w, http.StatusOK, agentapi.CertificateFiles{FullChain: string(chain), PrivKey: string(key)})
			return
		}
	}
	writeError(w, http.StatusInternalServerError, err)
}
