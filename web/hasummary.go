// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"fmt"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/models"
)

// An HA pair as one thing (dev/design-ha-usability.md): which host is active,
// whether the standby is ready, whether the configuration is on both, and so
// whether the pair can fail over now. Computed here, not in the agent: the
// replication is portitor-config's, and the agent's HA status stays cheap for
// the witness.

// The checks' results.
const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "fail"
)

// haPathQuiet is how long a heartbeat path may go unanswered before the pair
// is said to run on the other alone (the agent's haDeadAfter, with margin).
const haPathQuiet = 3 * time.Second

// haWitnessQuiet is how long the active host may go without the witness's
// vote (renewed every second) before failover is said to be by hand only.
const haWitnessQuiet = 10 * time.Second

// haCheck is one of a pair's checks.
type haCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// haPairSummary is an HA pair's summary.
type haPairSummary struct {
	// Name is the primary's.
	Name      string `json:"name"`
	Primary   string `json:"primary"`
	Secondary string `json:"secondary"`
	// Active is the host that is active, "" for none.
	Active string `json:"active"`
	// FailoverReady: no check fails.
	FailoverReady bool      `json:"failover_ready"`
	Checks        []haCheck `json:"checks"`
}

// configCopy is what is known of the secondary's copy of the configuration:
// from the primary's replication, or from the replica's own last copy.
type configCopy struct {
	// Known: there is anything to say (false: a portitor-config that
	// can't tell, as one of a release before the copy was reported).
	Known      bool
	Replicated bool
	// At is when the copy was last made or reported.
	At    *time.Time
	Error string
}

// pairSummary sums up a pair from its two hosts' HA status (nil: the agent
// didn't answer), the witness setting and the configuration's copy.
func pairSummary(names [2]string, sts [2]*agentapi.HAStatus, witness string, cp configCopy, now time.Time) haPairSummary {
	p := haPairSummary{Name: names[0], Primary: names[0], Secondary: names[1]}
	add := func(name, status, format string, a ...any) {
		p.Checks = append(p.Checks, haCheck{Name: name, Status: status, Message: fmt.Sprintf(format, a...)})
	}
	act := activeOf(sts)
	both := sts[0] != nil && sts[1] != nil && sts[0].State == agentapi.HAActive && sts[1].State == agentapi.HAActive
	switch {
	case both:
		// Never for long: the one at the lower term closes.
		add("active", checkWarn, "both report active for a moment; %s is closing", names[1-act])
		p.Active = names[act]
	case act >= 0:
		p.Active = names[act]
		add("active", checkOK, "%s is active", names[act])
	default:
		add("active", checkFail, "no host is active: traffic does not pass")
	}

	// The standby: the other host, or both when none is active.
	sb := 1
	if act == 1 {
		sb = 0
	}
	switch st := sts[sb]; {
	case act < 0:
		// Said above.
	case st == nil:
		add("standby", checkFail, "%s's agent does not answer: the pair cannot fail over", names[sb])
	case st.State == agentapi.HAStale:
		add("standby", checkFail, "%s is a primary taken over by a promotion: update it as the secondary", names[sb])
	case st.State != agentapi.HAStandby:
		add("standby", checkFail, "%s is %s: it does not hear its peer", names[sb], st.State)
	case sts[act] != nil && st.Health >= 0 && sts[act].Health >= 0 && st.Health < sts[act].Health:
		add("standby", checkWarn, "%s is ready, with %d of %d monitored interfaces up (%s has %d)", names[sb], st.Health, st.Monitored, names[act], sts[act].Health)
	default:
		add("standby", checkOK, "%s is ready", names[sb])
	}

	// The paths, as the host that answers sees them (the active one first).
	if st := firstOf(sts, act); st != nil {
		link, mgmt := recent(st.LinkSeen, now, haPathQuiet), recent(st.MgmtSeen, now, haPathQuiet)
		switch {
		case link && mgmt:
			add("paths", checkOK, "the hosts hear each other over the HA link and management")
		case link:
			add("paths", checkWarn, "management is silent between the hosts: losing the HA link now closes the pair")
		case mgmt:
			add("paths", checkWarn, "the HA link is silent: losing management now closes the pair")
		case st.LinkSeen == nil && st.MgmtSeen == nil && st.PeerAlive:
			add("paths", checkOK, "the hosts hear each other (an agent before this release tells no path)")
		default:
			add("paths", checkFail, "the hosts do not hear each other")
		}
	}

	switch {
	case witness != models.HAWitnessExternal:
		add("witness", checkWarn, "the witness is the primary's portitor-config: losing the primary takes a step by hand")
	case act >= 0 && sts[act] != nil && !recent(sts[act].WitnessSeen, now, haWitnessQuiet):
		add("witness", checkWarn, "the witness has not voted for %s lately: a failover would take a step by hand", names[act])
	case act >= 0:
		add("witness", checkOK, "the external witness votes")
	}

	// One check of the two watchdogs, the worse one's status.
	wd := haCheck{Name: "watchdog"}
	for i, st := range sts {
		if st == nil {
			continue
		}
		status, msg := checkOK, names[i]+" has a hardware watchdog"
		switch st.Watchdog {
		case agentapi.HAWatchdogNone:
			status, msg = checkFail, names[i]+" has no watchdog: it will not open on the witness's vote"
		case agentapi.HAWatchdogSoft:
			status, msg = checkWarn, names[i]+" has softdog: a hung kernel is not reset"
		case agentapi.HAWatchdogHardware:
		default:
			continue
		}
		if wd.Status == "" || worse(status, wd.Status) {
			wd.Status = status
		}
		wd.Message = joinNonEmpty(wd.Message, msg)
	}
	if wd.Status != "" {
		p.Checks = append(p.Checks, wd)
	}

	switch {
	case !cp.Known:
	case cp.Error != "":
		add("configuration", checkFail, "the secondary's copy failed: %s", cp.Error)
	case !cp.Replicated:
		add("configuration", checkFail, "the secondary has not copied the configuration: losing the primary now loses it")
	case cp.At != nil && now.Sub(*cp.At) > 2*replicaEvery:
		add("configuration", checkWarn, "the secondary last copied the configuration at %s", cp.At.Format(time.RFC3339))
	default:
		add("configuration", checkOK, "the configuration is on both hosts")
	}

	if sts[0] != nil && sts[1] != nil {
		v0, v1 := sts[0].Version, sts[1].Version
		switch {
		case v0 == "" || v1 == "":
		case v0 != v1:
			add("release", checkWarn, "the hosts run different releases (%s %s, %s %s): update them together, the secondary first", names[0], v0, names[1], v1)
		default:
			add("release", checkOK, "both run %s", v0)
		}
	}

	if st := firstOf(sts, act); st != nil {
		dh := haCheck{Name: "dhcp", Status: checkWarn}
		for _, d := range st.DHCP {
			if d.Error != "" {
				dh.Message = joinNonEmpty(dh.Message, d.Instance+"'s DHCP leases don't reach the standby: "+d.Error)
			}
		}
		if dh.Message != "" {
			p.Checks = append(p.Checks, dh)
		}
	}

	p.FailoverReady = true
	for _, c := range p.Checks {
		if c.Status == checkFail {
			p.FailoverReady = false
		}
	}
	return p
}

// worse tells whether check status a is worse than b.
func worse(a, b string) bool {
	rank := map[string]int{checkOK: 0, checkWarn: 1, checkFail: 2}
	return rank[a] > rank[b]
}

// firstOf is the status of host i when it answered, else the other's.
func firstOf(sts [2]*agentapi.HAStatus, i int) *agentapi.HAStatus {
	if i >= 0 && sts[i] != nil {
		return sts[i]
	}
	if sts[0] != nil {
		return sts[0]
	}
	return sts[1]
}

func recent(t *time.Time, now time.Time, within time.Duration) bool {
	return t != nil && now.Sub(*t) < within
}

// haPairs sums up the pairs among the firewalls, from their status (by id).
func (s *Server) haPairs(ctx context.Context, fws []models.Firewall, sts map[uint]*agentapi.HAStatus) []haPairSummary {
	var out []haPairSummary
	for _, sec := range fws {
		if sec.HAPrimaryID == nil {
			continue
		}
		var prim *models.Firewall
		for i := range fws {
			if fws[i].ID == *sec.HAPrimaryID {
				prim = &fws[i]
			}
		}
		if prim == nil {
			continue
		}
		out = append(out, pairSummary([2]string{prim.Name, sec.Name}, [2]*agentapi.HAStatus{sts[prim.ID], sts[sec.ID]},
			prim.HAWitness, s.configCopy(ctx), time.Now()))
	}
	return out
}

// configCopy is what this portitor-config knows of the secondary's copy.
func (s *Server) configCopy(ctx context.Context) configCopy {
	// A console command's process has none of the service's copy reports:
	// it can't tell.
	if !s.serving.Load() {
		return configCopy{}
	}
	if !s.isReplica() {
		r := s.replication(ctx)
		if r == nil {
			return configCopy{}
		}
		return configCopy{Known: true, Replicated: r.Replicated, At: r.Reported, Error: r.Error}
	}
	st := s.haStatus(ctx)
	// The replica copies every replicaEvery: a recent copy without an
	// error is the primary's configuration.
	return configCopy{Known: true, Replicated: st.CopyErr == "" && st.LastCopy != nil, At: st.LastCopy, Error: st.CopyErr}
}
