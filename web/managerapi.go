// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// The manager API of portitor-config (/manager/v1): a manager
// (portitor-web managing this firewall) pushes whole virtual firewalls as
// bundles, which become managed here (managed.go), commits them, and
// compares what it has with what is here by InstanceHash. It
// authenticates with the token in manager_token_file, and names itself
// in every write ("manager"), which marks what it owns.

var managerNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// InstanceHash identifies an instance's configuration as the builder makes
// it, whatever its name and row ids: equal on a manager and its firewall
// when they agree.
func InstanceHash(db *gorm.DB, name string) (string, error) {
	doc, err := builder.BuildInstances(db, 0, map[string]bool{name: true})
	var ve *fwconfig.ValidationError
	if err != nil && !errors.As(err, &ve) {
		return "", err
	}
	in := doc.Instance(name)
	if in == nil {
		return "", bad("no such virtual firewall: " + name)
	}
	cp := *in
	cp.Name = ""
	cp.Rules = append([]fwconfig.Rule(nil), in.Rules...)
	for i := range cp.Rules {
		cp.Rules[i].ID = 0
	}
	b, _ := json.Marshal(cp)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// managerAuth lets the manager's token in.
func (s *Server) managerAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		tok, err := os.ReadFile(s.cfg.ManagerTokenFile)
		want := strings.TrimSpace(string(tok))
		if err != nil || len(want) < 32 {
			return errJSON(c, http.StatusServiceUnavailable, "no manager token (manager_token_file)")
		}
		got := c.Request().Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+want)) != 1 {
			slog.Warn("manager api: bad token", "remote", c.RealIP())
			return errJSON(c, http.StatusUnauthorized, "unauthorized")
		}
		return next(c)
	}
}

func (s *Server) registerManagerAPI(e *echo.Echo) {
	g := e.Group("/manager/v1", requireJSON, noStore, s.managerAuth)
	g.GET("/state", s.handleManagerState)
	g.GET("/instances/:name/bundle", s.handleManagerBundle)
	g.PUT("/instances/:name", s.handleManagerPush)
	g.DELETE("/instances/:name", s.handleManagerDelete)
	g.PUT("/users", s.handleManagerUsers)
	g.POST("/commit", s.handleManagerCommit)
	g.POST("/confirm", s.handleManagerConfirm)
	g.POST("/rollback", s.handleManagerRollback)
}

// ManagedState is what portitor-config tells its manager.
type ManagedState struct {
	Schema    int64             `json:"schema"`
	Instances []ManagedInstance `json:"instances"`
	// Pending: a commit waits for confirmation.
	Pending bool  `json:"pending"`
	Commit  int64 `json:"commit"`
}

type ManagedInstance struct {
	Name      string `json:"name"`
	Default   bool   `json:"default"`
	ManagedBy string `json:"managed_by,omitempty"`
	Diverged  bool   `json:"diverged,omitempty"`
	Hash      string `json:"hash"`
}

func (s *Server) handleManagerState(c *echo.Context) error {
	st := ManagedState{Instances: []ManagedInstance{}}
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	if err := sqlDB.QueryRowContext(c.Request().Context(), "SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&st.Schema); err != nil {
		return err
	}
	var ins []models.Instance
	if err := s.db.Order("name").Find(&ins).Error; err != nil {
		return err
	}
	for _, in := range ins {
		h, err := InstanceHash(s.db, in.Name)
		if err != nil {
			return dbError(c, err)
		}
		st.Instances = append(st.Instances, ManagedInstance{Name: in.Name, Default: in.IsDefault, ManagedBy: in.ManagedBy, Diverged: in.Diverged, Hash: h})
	}
	deps, err := s.settlePending(c.Request().Context())
	if err != nil {
		return err
	}
	st.Pending = len(deps) > 0
	if st.Commit, err = s.liveCommit(); err != nil {
		return err
	}
	return c.JSON(http.StatusOK, st)
}

func (s *Server) handleManagerBundle(c *echo.Context) error {
	var in models.Instance
	if err := s.db.Where("name = ?", c.Param("name")).First(&in).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "no such virtual firewall")
	}
	b, err := ExportBundle(c.Request().Context(), s.db, in.ID)
	if err != nil {
		return dbError(c, err)
	}
	return c.JSON(http.StatusOK, b)
}

// handleManagerPush puts the manager's version of a virtual firewall in
// place, managed by it.
func (s *Server) handleManagerPush(c *echo.Context) error {
	var req struct {
		Manager   string  `json:"manager"`
		Overwrite bool    `json:"overwrite"`
		Bundle    *Bundle `json:"bundle"`
	}
	if err := c.Bind(&req); err != nil || req.Bundle == nil || !managerNameRe.MatchString(req.Manager) {
		return errJSON(c, http.StatusBadRequest, "manager (lowercase name) and bundle are required")
	}
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	name := c.Param("name")
	id, problems, err := importBundle(c.Request().Context(), s.db, req.Bundle, name, 0, importOptions{Manager: req.Manager, Overwrite: req.Overwrite})
	var conflict *bundleConflict
	switch {
	case errors.As(err, &conflict):
		return errJSON(c, http.StatusConflict, conflict.msg)
	case err != nil:
		return dbError(c, err)
	}
	slog.Info("manager push", "manager", req.Manager, "instance", name, "overwrite", req.Overwrite)
	if problems == nil {
		problems = []string{}
	}
	return c.JSON(http.StatusOK, map[string]any{"id": id, "problems": problems, "left": req.Bundle.Left})
}

// handleManagerDelete removes a virtual firewall the manager pushed.
func (s *Server) handleManagerDelete(c *echo.Context) error {
	manager := c.QueryParam("manager")
	var in models.Instance
	if err := s.db.Where("name = ?", c.Param("name")).First(&in).Error; err != nil {
		return errJSON(c, http.StatusNotFound, "no such virtual firewall")
	}
	if in.ManagedBy == "" || in.ManagedBy != manager {
		return errJSON(c, http.StatusConflict, fmt.Sprintf("virtual firewall %s is not %s's", in.Name, manager))
	}
	err := s.db.Transaction(func(tx *gorm.DB) error {
		if err := deleteInstance(tx, &in); err != nil {
			return err
		}
		return tx.Delete(&in).Error
	})
	if err != nil {
		return dbError(c, err)
	}
	slog.Info("manager delete", "manager", manager, "instance", in.Name)
	return c.NoContent(http.StatusNoContent)
}

func (s *Server) handleManagerCommit(c *echo.Context) error {
	var req struct {
		Manager        string `json:"manager"`
		ConfirmTimeout *int   `json:"confirm_timeout"`
	}
	_ = c.Bind(&req)
	if deps, err := s.settlePending(c.Request().Context()); err != nil {
		return err
	} else if len(deps) > 0 {
		return errJSON(c, http.StatusConflict, errPending.Error())
	}
	res, err := s.deploy(c.Request().Context(), "manager "+req.Manager, req.ConfirmTimeout, nil)
	var ve *fwconfig.ValidationError
	switch {
	case errors.As(err, &ve):
		return problemsResponse(c, err)
	case errors.Is(err, errPending):
		return errJSON(c, http.StatusConflict, err.Error())
	case err != nil && res != nil:
		return c.JSON(http.StatusBadGateway, map[string]any{"error": err.Error(), "commit": res})
	case err != nil:
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, res)
}

func (s *Server) handleManagerConfirm(c *echo.Context) error {
	deps, err := s.finishPending(c.Request().Context(), "the manager", true)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{"deployments": deps})
}

func (s *Server) handleManagerRollback(c *echo.Context) error {
	deps, err := s.finishPending(c.Request().Context(), "the manager", false)
	if err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusOK, map[string]any{"deployments": deps})
}

// finishPending confirms (or rolls back) every deployment waiting for it.
func (s *Server) finishPending(ctx context.Context, by string, confirm bool) ([]models.Deployment, error) {
	deps, err := s.pendingDeployments()
	if err != nil {
		return nil, err
	}
	if len(deps) == 0 {
		return nil, bad("no change is waiting for confirmation")
	}
	var errs []string
	for i := range deps {
		dep := &deps[i]
		fw, err := s.finishDeployment(ctx, dep, confirm)
		if err != nil {
			errs = append(errs, firewallName(fw)+err.Error())
			continue
		}
		if confirm {
			dep.Status, dep.Message = "confirmed", "confirmed by "+by
		} else {
			dep.Status, dep.Message = "rolled_back", "rolled back by "+by
		}
		s.db.Save(dep)
	}
	if len(errs) > 0 {
		return deps, errors.New(strings.Join(errs, "; "))
	}
	return deps, nil
}
