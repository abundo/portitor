// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// queryLog keeps the DNS queries BIND logs (render.NamedConf sends them to
// the journal) for the GUI's log panel. It follows the journal of each
// instance's named unit with journalctl, which only reads, and keeps the
// queries that pass the instance's filters.
type queryLog struct {
	dryRun  bool
	entries *ring[agentapi.DNSQueryEntry]

	mu        sync.Mutex
	followers map[string]*queryLogRun // by instance
	wg        sync.WaitGroup
}

// queryLogItem is an instance whose queries are logged.
type queryLogItem struct {
	unit   string // the named unit
	filter fwconfig.DNSQueryLog
}

type queryLogRun struct {
	item   queryLogItem
	cancel context.CancelFunc
}

func newQueryLog(dryRun bool) *queryLog {
	return &queryLog{
		dryRun:    dryRun,
		entries:   newRing(2000, func(e *agentapi.DNSQueryEntry) *int64 { return &e.ID }),
		followers: map[string]*queryLogRun{},
	}
}

// After returns the logged queries with an id above after.
func (q *queryLog) After(after int64) []agentapi.DNSQueryEntry {
	return q.entries.After(after)
}

// Reconcile follows the instances of want and stops following the others;
// a changed unit or filter starts again.
func (q *queryLog) Reconcile(want map[string]queryLogItem) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for name, r := range q.followers {
		if it, ok := want[name]; !ok || !reflect.DeepEqual(it, r.item) {
			r.cancel()
			delete(q.followers, name)
		}
	}
	for name, it := range want {
		if _, ok := q.followers[name]; ok {
			continue
		}
		log := slog.With("instance", name)
		if q.dryRun {
			log.Info("dry-run: not following the DNS query log")
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		q.followers[name] = &queryLogRun{item: it, cancel: cancel}
		q.wg.Go(func() { q.run(ctx, name, it, log) })
	}
}

func (q *queryLog) Stop() {
	q.Reconcile(nil)
	q.wg.Wait()
}

// run follows until ctx is done, starting again when journalctl fails.
func (q *queryLog) run(ctx context.Context, instance string, it queryLogItem, log *slog.Logger) {
	f := newQueryFilter(it.filter)
	for {
		err := q.follow(ctx, instance, it.unit, f)
		if ctx.Err() != nil {
			return
		}
		log.Warn("DNS query log", "err", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
	}
}

func (q *queryLog) follow(ctx context.Context, instance, unit string, f queryFilter) error {
	cmd := exec.CommandContext(ctx, "journalctl", "--follow", "--lines=0", "--output=json",
		"--unit="+unit, "SYSLOG_FACILITY=3")
	stderr := &tailBuffer{max: 1 << 10}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		e, ok := parseJournalQuery(sc.Bytes())
		if !ok || !f.match(e) {
			continue
		}
		e.Instance = instance
		q.entries.add(e)
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("%v: %s", err, msg)
	}
	if err == nil {
		err = errors.New("journalctl exited")
	}
	return err
}

// queryLine is BIND's query log message:
//
//	client @0x7f... 192.168.1.10#50123 (www.example.com): query: www.example.com IN A +E(0)K (192.168.1.1)
//
// with "view <name>: " before "query:" when the server has views.
var queryLine = regexp.MustCompile(`^client (?:@\S+ )?(\S+)#(\d+)(?: \([^)]*\))?: (?:view \S+: )?query: (\S+) (\S+) (\S+) (\S*)(?: \((\S+)\))?`)

// parseJournalQuery makes an entry of a journal record (journalctl's JSON)
// holding a query log message; ok is false for any other record.
func parseJournalQuery(line []byte) (e agentapi.DNSQueryEntry, ok bool) {
	var rec struct {
		Message  any    `json:"MESSAGE"` // a byte array when not UTF-8
		Realtime string `json:"__REALTIME_TIMESTAMP"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return e, false
	}
	msg, _ := rec.Message.(string)
	m := queryLine.FindStringSubmatch(msg)
	if m == nil {
		return e, false
	}
	client, err := netip.ParseAddr(m[1])
	if err != nil {
		return e, false
	}
	port, _ := strconv.ParseUint(m[2], 10, 16)
	e = agentapi.DNSQueryEntry{
		Time:       time.Now(),
		Client:     client.Unmap().String(),
		ClientPort: uint16(port),
		Name:       m[3],
		Class:      m[4],
		Type:       m[5],
		Flags:      m[6],
		Server:     m[7],
	}
	if us, err := strconv.ParseInt(rec.Realtime, 10, 64); err == nil {
		e.Time = time.UnixMicro(us)
	}
	return e, true
}

// queryFilter is an instance's fwconfig.DNSQueryLog, parsed.
type queryFilter struct {
	clients []netip.Prefix
	names   []string // lower case, no trailing dot
	types   []string
}

func newQueryFilter(f fwconfig.DNSQueryLog) queryFilter {
	var qf queryFilter
	for _, c := range f.Clients {
		if p, err := netip.ParsePrefix(c); err == nil {
			qf.clients = append(qf.clients, p.Masked())
		}
	}
	for _, n := range f.Names {
		qf.names = append(qf.names, strings.ToLower(strings.TrimSuffix(n, ".")))
	}
	qf.types = f.Types
	return qf
}

func (f queryFilter) match(e agentapi.DNSQueryEntry) bool {
	if len(f.clients) > 0 {
		a, err := netip.ParseAddr(e.Client)
		if err != nil || !slices.ContainsFunc(f.clients, func(p netip.Prefix) bool { return p.Contains(a) }) {
			return false
		}
	}
	if len(f.names) > 0 {
		name := strings.ToLower(strings.TrimSuffix(e.Name, "."))
		if !slices.ContainsFunc(f.names, func(n string) bool { return name == n || strings.HasSuffix(name, "."+n) }) {
			return false
		}
	}
	if len(f.types) > 0 && !slices.Contains(f.types, e.Type) {
		return false
	}
	return true
}
