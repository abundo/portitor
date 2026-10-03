// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/cron"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// IP lists and scheduled tasks. Rules refer to a list as "@name" in their
// address lists, so renaming a list rewrites them, and a list that a rule
// or task uses cannot be deleted.

// checkDocPart runs fwconfig's validation of the document-level entries
// (IP lists, tasks) for a quick answer when an entry is saved, keeping
// the problems that start with prefix.
func checkDocPart(doc fwconfig.Document, prefix string) error {
	doc.Version = fwconfig.Version
	err := doc.Validate()
	if err == nil {
		return nil
	}
	ve, ok := err.(*fwconfig.ValidationError)
	if !ok {
		return err
	}
	var msgs []string
	for _, p := range ve.Problems {
		if rest, ok := strings.CutPrefix(p, prefix); ok {
			msgs = append(msgs, rest)
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	return bad(strings.Join(msgs, "; "))
}

func ipListDoc(l *models.IpList) fwconfig.IPList {
	return fwconfig.IPList{Name: l.Name, Source: l.Source, URL: l.Url, Username: l.Username, Password: l.Password, APIKey: l.ApiKey}
}

func prepareIpList(tx *gorm.DB, l, old *models.IpList) error {
	l.Name = strings.TrimSpace(l.Name)
	if !fwconfig.ValidName(l.Name) || strings.HasPrefix(l.Name, "@") {
		return bad("name: no control characters, not starting with @")
	}
	if err := itemFolder(tx, &l.FolderID, models.ObjectFolderIpLists); err != nil {
		return err
	}
	if l.Source == "" {
		l.Source = fwconfig.IPListURL
	}
	if err := oneOf("source", l.Source, fwconfig.IPListCrowdSec, fwconfig.IPListURL); err != nil {
		return err
	}
	l.Url = strings.TrimSpace(l.Url)
	if err := fwconfig.ValidURL(l.Url); err != nil {
		return bad("URL: " + err.Error())
	}
	l.Username = strings.TrimSpace(l.Username)
	if pw := l.NewPassword; pw != "" {
		l.Password = pw
	}
	if key := strings.TrimSpace(l.NewApiKey); key != "" {
		l.ApiKey = key
	}
	l.NewPassword, l.NewApiKey = "", ""
	if l.Source == fwconfig.IPListCrowdSec {
		l.Username, l.Password = "", ""
		if l.ApiKey == "" {
			return bad("CrowdSec needs a bouncer API key (cscli bouncers add portitor)")
		}
	} else {
		l.ApiKey = ""
		if l.Username == "" {
			l.Password = ""
		}
	}
	if fwconfig.PlainTextCredentials(ipListDoc(l)) {
		what := "password"
		if l.Source == fwconfig.IPListCrowdSec {
			what = "API key"
		}
		return bad("URL: http:// would send the " + what + " unencrypted; use https:// (or a loopback address such as 127.0.0.1)")
	}
	if err := checkDocPart(fwconfig.Document{IPLists: []fwconfig.IPList{ipListDoc(l)}}, fmt.Sprintf("ip list %q: ", l.Name)); err != nil {
		return err
	}
	if old != nil && old.Name != l.Name {
		return eachIPListRef(tx, func(_ string, entry *string) bool {
			if *entry == fwconfig.IPListRef+old.Name {
				*entry = fwconfig.IPListRef + l.Name
				return true
			}
			return false
		})
	}
	return nil
}

func presentIpList(l *models.IpList) {
	l.HasPassword, l.HasApiKey = l.Password != "", l.ApiKey != ""
	l.NewPassword, l.NewApiKey = "", ""
}

func deleteIpList(tx *gorm.DB, l *models.IpList) error {
	var users []string
	err := eachIPListRef(tx, func(where string, entry *string) bool {
		if *entry == fwconfig.IPListRef+l.Name && (len(users) == 0 || users[len(users)-1] != where) {
			users = append(users, where)
		}
		return false
	})
	if err != nil {
		return err
	}
	var tasks []string
	tx.Model(&models.Task{}).Where("ip_list_id = ?", l.ID).Order("name").Pluck("name", &tasks)
	for _, t := range tasks {
		users = append(users, "task "+t)
	}
	if len(users) > 0 {
		if len(users) > 5 {
			users = append(users[:5], "...")
		}
		return bad(fmt.Sprintf("%s is used by %s", l.Name, strings.Join(users, ", ")))
	}
	return nil
}

// eachIPListRef calls visit for every rule address entry, where IP list
// references can be. Rules where visit changed an entry are saved.
func eachIPListRef(tx *gorm.DB, visit func(where string, entry *string) bool) error {
	instName := map[uint]string{}
	var instances []models.Instance
	if err := tx.Find(&instances).Error; err != nil {
		return err
	}
	for _, in := range instances {
		instName[in.ID] = in.Name
	}
	var rules []models.Rule
	if err := tx.Order("position, id").Find(&rules).Error; err != nil {
		return err
	}
	names := ruleNamer{}
	for _, r := range rules {
		where := fmt.Sprintf("%s in %s", names.rule(r), instName[r.InstanceID])
		changed := false
		for _, list := range []models.StringList{r.SrcAddrs, r.DstAddrs} {
			for i := range list {
				if visit(where, &list[i]) {
					changed = true
				}
			}
		}
		if changed {
			if err := tx.Model(&models.Rule{}).Where("id = ?", r.ID).UpdateColumns(map[string]any{"src_addrs": r.SrcAddrs, "dst_addrs": r.DstAddrs}).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func checkIPListRef(tx *gorm.DB, field, name string) error {
	var n int64
	tx.Model(&models.IpList{}).Where("name = ?", name).Count(&n)
	if n == 0 {
		return bad(fmt.Sprintf("%s: no IP list named %q", field, name))
	}
	return nil
}

func prepareTask(tx *gorm.DB, t, _ *models.Task) error {
	t.Name = strings.TrimSpace(t.Name)
	if !fwconfig.ValidFileName(t.Name) {
		return bad("name: no control characters or /, not . or .., at most 255 bytes")
	}
	t.Schedule = strings.Join(strings.Fields(t.Schedule), " ")
	if _, err := cron.Parse(t.Schedule); err != nil {
		return bad("schedule: " + err.Error())
	}
	if err := oneOf("kind", t.Kind, fwconfig.TaskIPList, fwconfig.TaskCommand); err != nil {
		return err
	}
	task := fwconfig.Task{Name: t.Name, Schedule: t.Schedule, Kind: t.Kind}
	doc := fwconfig.Document{Tasks: []fwconfig.Task{task}}
	if t.Kind == fwconfig.TaskIPList {
		t.Command, t.Timeout = "", 0
		if t.IpListID != nil && *t.IpListID == 0 {
			t.IpListID = nil
		}
		var l models.IpList
		if t.IpListID == nil || tx.First(&l, *t.IpListID).Error != nil {
			return bad("pick the IP list to download")
		}
		doc.Tasks[0].IPList = l.Name
		doc.IPLists = []fwconfig.IPList{ipListDoc(&l)}
	} else {
		t.IpListID = nil
		t.Command = strings.TrimSpace(t.Command)
		doc.Tasks[0].Command, doc.Tasks[0].Timeout = t.Command, t.Timeout
	}
	return checkDocPart(doc, fmt.Sprintf("task %q: ", t.Name))
}

// handleTaskRun runs a task on the firewall now.
func (s *Server) handleTaskRun(c *echo.Context) error {
	var t models.Task
	if !s.loadByID(c, &t) {
		return nil
	}
	return s.startOnAgent(c, t.Name, func(a agentAPI) error { return a.RunTask(c.Request().Context(), t.Name) })
}

// handleIPListRefresh downloads an IP list on the firewall now.
func (s *Server) handleIPListRefresh(c *echo.Context) error {
	var l models.IpList
	if !s.loadByID(c, &l) {
		return nil
	}
	return s.startOnAgent(c, l.Name, func(a agentAPI) error { return a.RefreshIPList(c.Request().Context(), l.Name) })
}

// loadByID loads the row with the :id path parameter into dst, or answers
// 404 and returns false.
func (s *Server) loadByID(c *echo.Context, dst any) bool {
	id, err := echo.PathParam[uint](c, "id")
	if err == nil {
		err = s.db.First(dst, id).Error
	}
	if err != nil {
		_ = errJSON(c, http.StatusNotFound, "not found")
		return false
	}
	return true
}

func (s *Server) startOnAgent(c *echo.Context, name string, start func(agentAPI) error) error {
	a, _, err := s.agent()
	if err != nil {
		return agentError(c, err)
	}
	if err := start(a); err != nil {
		return agentError(c, err)
	}
	return c.JSON(http.StatusAccepted, map[string]any{"started": name})
}

// handleSchedulePreview parses ?schedule= and returns its next runs in
// portitor-web's time zone, for the task editor.
func (s *Server) handleSchedulePreview(c *echo.Context) error {
	sched, err := cron.Parse(c.QueryParam("schedule"))
	if err != nil {
		return c.JSON(http.StatusOK, map[string]any{"error": err.Error()})
	}
	next := []time.Time{}
	t := time.Now()
	for range 5 {
		if t = sched.Next(t); t.IsZero() {
			break
		}
		next = append(next, t)
	}
	return c.JSON(http.StatusOK, map[string]any{"next": next})
}
