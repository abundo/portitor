// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// The firewall's check action (dev/design-ha-usability.md, part 2): its pair's
// summary (hasummary.go) and what only a look at both hosts tells: the
// secondary has the interfaces the pair runs by name, and the HA link reaches
// the peer alone. Run by the GUI's Check pair, the CLI's tools and NETCONF;
// on a firewall in no pair it says so.

func init() {
	registerAction("/firewall", "check", checkPair)
	registerAction("/firewall", "test-switchover", testSwitchover)
}

// pairHost is what the check asks of each host.
type pairHost struct {
	fw   models.Firewall
	st   *agentapi.Status
	nb   *agentapi.NeighboursResponse
	err  string
	ha   *agentapi.HAStatus
	nics []string
}

// pairOf is the primary and secondary of the pair the entry's firewall is
// in; an error answer when there is none.
func pairOf(s *Server, c *echo.Context, a *actionCtx) (prim, sec *models.Firewall, err error) {
	name := a.entry.Leaf("name")
	fws, err := s.rec.Firewalls()
	if err != nil {
		return nil, nil, err
	}
	i := slices.IndexFunc(fws, func(f models.Firewall) bool { return f.Name == name })
	if i < 0 {
		return nil, nil, errJSON(c, http.StatusNotFound, "no firewall "+name+" has been committed")
	}
	if p := fws[i].HAPrimaryID; p != nil {
		sec = &fws[i]
		if j := slices.IndexFunc(fws, func(f models.Firewall) bool { return f.ID == *p }); j >= 0 {
			prim = &fws[j]
		}
	} else if q, _ := s.secondaryOf(fws[i].ID); q != nil {
		prim, sec = &fws[i], q
	}
	if prim == nil || sec == nil {
		return nil, nil, errJSON(c, http.StatusConflict, name+" is not in a firewall cluster")
	}
	return prim, sec, nil
}

// checkedPair is the pair's summary with the checks only a look at both
// hosts gives.
func (s *Server) checkedPair(ctx context.Context, prim, sec *models.Firewall) haPairSummary {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	hosts := [2]*pairHost{{fw: *prim}, {fw: *sec}}
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Go(func() { s.askHost(ctx, h) })
	}
	wg.Wait()

	p := pairSummary([2]string{prim.Name, sec.Name}, [2]*agentapi.HAStatus{hosts[0].ha, hosts[1].ha},
		prim.HAWitness, s.configCopy(ctx), time.Now())
	for _, h := range hosts {
		if h.err != "" {
			p.Checks = append(p.Checks, haCheck{Name: "agent " + h.fw.Name, Status: checkFail, Message: h.fw.Name + "'s agent: " + h.err})
		}
	}
	doc, _ := s.liveDocument(sec.ID)
	if doc == nil {
		doc, _ = s.liveDocument(prim.ID)
	}
	if doc != nil {
		p.Checks = append(p.Checks, interfaceCheck(doc, hosts))
		if ck, ok := haLinkCheck(doc, hosts); ok {
			p.Checks = append(p.Checks, ck)
		}
	}
	p.FailoverReady = !slices.ContainsFunc(p.Checks, func(c haCheck) bool { return c.Status == checkFail })
	return p
}

func checkPair(s *Server, c *echo.Context, a *actionCtx) error {
	// The hosts' names, releases, interfaces and neighbours: for those who
	// read every instance, as GET /api/firewalls (readsEverything).
	if !currentAccess(c).readsAll() {
		return errJSON(c, http.StatusForbidden, "only a global admin or viewer may check a cluster")
	}
	prim, sec, err := pairOf(s, c, a)
	if prim == nil {
		return err
	}
	p := s.checkedPair(c.Request().Context(), prim, sec)
	return c.JSON(http.StatusOK, map[string]any{
		"primary": p.Primary, "secondary": p.Secondary, "active": p.Active,
		"failover-ready": p.FailoverReady, "checks": p.Checks,
	})
}

// switchTimeout bounds the wait for the other host to report active.
const switchTimeout = 15 * time.Second

// switchSettle is the wait before switching back: a host that handed over
// takes no vote until its promise ends (agent haVoteMax), and the pair's
// leases settle.
var switchSettle = 5 * time.Second

// testSwitchover switches the pair over and back, once it checks ready, and
// tells how long each took: from the request until the other host's agent
// reported active (its gate open). That is the hosts' side, measured every
// 100 ms; what a client loses (a packet or two) it can't see.
func testSwitchover(s *Server, c *echo.Context, a *actionCtx) error {
	prim, sec, err := pairOf(s, c, a)
	if prim == nil {
		return err
	}
	ctx := c.Request().Context()
	p := s.checkedPair(ctx, prim, sec)
	if !p.FailoverReady {
		var why []string
		for _, ck := range p.Checks {
			if ck.Status == checkFail {
				why = append(why, ck.Message)
			}
		}
		return errJSON(c, http.StatusConflict, "the cluster can't fail over now: "+strings.Join(why, "; "))
	}
	pair := map[string]*models.Firewall{prim.Name: prim, sec.Name: sec}
	from := pair[p.Active]
	to := sec
	if from == sec {
		to = prim
	}
	user := currentUser(c).Username
	there, err := s.switchOver(ctx, from, to)
	if err != nil {
		return agentError(c, err)
	}
	slog.Info("cluster: switchover test", "from", from.Name, "to", to.Name, "ms", there.Milliseconds(), "user", user)
	// Back even when the request goes away meanwhile (a closed tab, a
	// proxy's timeout): a test leaves the pair as it found it.
	ctx = context.WithoutCancel(ctx)
	time.Sleep(switchSettle)
	back, err := s.switchOver(ctx, to, from)
	if err != nil {
		return errJSON(c, http.StatusBadGateway, fmt.Sprintf("switched over to %s in %d ms, but not back: %v (switch back by hand)", to.Name, there.Milliseconds(), err))
	}
	slog.Info("cluster: switchover test", "from", to.Name, "to", from.Name, "ms", back.Milliseconds(), "user", user)
	return c.JSON(http.StatusOK, map[string]any{
		"from": from.Name, "to": to.Name,
		"there-ms": there.Milliseconds(), "back-ms": back.Milliseconds(),
	})
}

// switchOver hands the pair over from the active host from to the other,
// and waits until to reports active; how long that took.
func (s *Server) switchOver(ctx context.Context, from, to *models.Firewall) (time.Duration, error) {
	af, err := s.newAgent(from)
	if err != nil {
		return 0, err
	}
	at, err := s.newAgent(to)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if err := af.HASwitchover(ctx); err != nil {
		return 0, fmt.Errorf("%s: %w", from.Name, err)
	}
	ctx, cancel := context.WithTimeout(ctx, switchTimeout)
	defer cancel()
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		if st := haOf(ctx, at); st != nil && st.State == agentapi.HAActive {
			return time.Since(start), nil
		}
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("%s did not report active within %s", to.Name, switchTimeout)
		case <-t.C:
		}
	}
}

// askHost fills in a host's status, neighbours and HA state.
func (s *Server) askHost(ctx context.Context, h *pairHost) {
	ag, err := s.newAgent(&h.fw)
	if err != nil {
		h.err = err.Error()
		return
	}
	if h.st, err = ag.Status(ctx); err != nil {
		h.err = err.Error()
		return
	}
	h.ha = h.st.HA
	for _, n := range h.st.NICs {
		h.nics = append(h.nics, n.Name)
	}
	h.nb, _ = ag.Neighbours(ctx)
}

// interfaceCheck: the hosts have the same of the enabled physical
// interfaces the pair's document names (the secondary runs the primary's
// by name). One missing on both is the commit's problem, not the pair's.
func interfaceCheck(doc *fwconfig.Document, hosts [2]*pairHost) haCheck {
	if hosts[0].st == nil || hosts[1].st == nil {
		return haCheck{Name: "interfaces", Status: checkWarn, Message: "not known: an agent does not answer"}
	}
	var missing []string
	for _, in := range doc.Instances {
		for _, ifc := range in.Interfaces {
			if ifc.Kind != fwconfig.KindPhysical || !ifc.Enabled {
				continue
			}
			has := [2]bool{slices.Contains(hosts[0].nics, ifc.Name), slices.Contains(hosts[1].nics, ifc.Name)}
			for i := range hosts {
				if !has[i] && has[1-i] {
					missing = append(missing, hosts[i].fw.Name+" has no "+ifc.Name)
				}
			}
		}
	}
	if len(missing) > 0 {
		return haCheck{Name: "interfaces", Status: checkFail, Message: strings.Join(missing, "; ") + ": both hosts need the same interface names"}
	}
	return haCheck{Name: "interfaces", Status: checkOK, Message: "both hosts have the interfaces the cluster runs"}
}

// haLinkCheck: on the HA link, LLDP should hear the peer alone. A switch
// heard there may be one management goes through too, which would be one
// failure for both paths; it can't be proven either way, so only a warning.
func haLinkCheck(doc *fwconfig.Document, hosts [2]*pairHost) (haCheck, bool) {
	link := ""
	for _, in := range doc.Instances {
		for _, ifc := range in.Interfaces {
			if in.Default && ifc.HARole == fwconfig.HARoleLink {
				link = ifc.Name
			}
		}
	}
	if link == "" {
		return haCheck{}, false
	}
	var others []string
	heard := false
	for i, h := range hosts {
		if h.nb == nil {
			continue
		}
		peer := hosts[1-i].st
		for _, n := range h.nb.LLDP {
			if n.Interface != link {
				continue
			}
			heard = true
			if peer == nil || n.SystemName != peer.Hostname {
				others = append(others, h.fw.Name+" hears "+lldpName(n))
			}
		}
	}
	switch {
	case len(others) > 0:
		slices.Sort(others)
		others = slices.Compact(others)
		return haCheck{Name: "cluster-link", Status: checkWarn, Message: strings.Join(others, "; ") + " on the cluster link: if management goes through the same device, one failure stops the cluster"}, true
	case heard:
		return haCheck{Name: "cluster-link", Status: checkOK, Message: "the cluster link reaches the peer directly"}, true
	}
	return haCheck{}, false
}

func lldpName(n agentapi.LLDPNeighbour) string {
	if n.SystemName != "" {
		return n.SystemName
	}
	return n.ChassisID
}
