// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netconf

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// memory is a backend in memory; a confirmed commit waits for confirm or
// rollback.
type memory struct {
	current, running, before *datastore.Tree
	pending                  bool
	commits                  int
}

func (m *memory) Initial(context.Context) (*datastore.Tree, error) { return m.current.Clone(), nil }
func (m *memory) Running(context.Context) (*datastore.Tree, error) { return m.running.Clone(), nil }
func (m *memory) Commit(_ context.Context, t *datastore.Tree, o datastore.CommitOptions) (string, error) {
	if o.Validate {
		return "", nil
	}
	m.before = m.running
	m.current, m.running = t.Clone(), t.Clone()
	m.pending = o.Confirm != nil && *o.Confirm > 0
	m.commits++
	return "", nil
}

type allowAll struct{}

func (allowAll) CanRead(datastore.Path) bool  { return true }
func (allowAll) CanWrite(datastore.Path) bool { return true }

func newEnv() (*cli.Env, *memory) {
	root := schema.MustLoad()
	m := &memory{current: datastore.New(root), running: datastore.New(root)}
	env := &cli.Env{Store: datastore.NewStore(root, m, ""), Schema: root, User: "admin", Access: allowAll{}}
	env.Pending = func(context.Context) bool { return m.pending }
	env.Confirm = func(context.Context) (string, error) { m.pending = false; return "", nil }
	env.Rollback = func(context.Context) (string, error) {
		m.pending, m.running, m.current = false, m.before, m.before.Clone()
		return "", nil
	}
	return env, m
}

// client is a NETCONF client over a pipe.
type client struct {
	t  *testing.T
	f  *framer
	id int
}

func dial(t *testing.T, env *cli.Env, base11 bool) *client {
	t.Helper()
	a, b := net.Pipe()
	go Serve(context.Background(), env, a)
	t.Cleanup(func() { b.Close() })
	c := &client{t: t, f: newFramer(b)}
	hello, err := c.f.read()
	if err != nil || !strings.Contains(string(hello), "urn:ietf:params:netconf:capability:candidate:1.0") {
		t.Fatalf("hello: %s %v", hello, err)
	}
	caps := "<capability>urn:ietf:params:netconf:base:1.0</capability>"
	if base11 {
		caps += "<capability>urn:ietf:params:netconf:base:1.1</capability>"
	}
	if err := c.f.write([]byte(`<hello xmlns="` + nsBase + `"><capabilities>` + caps + `</capabilities></hello>`)); err != nil {
		t.Fatal(err)
	}
	c.f.chunked = base11
	return c
}

func (c *client) rpc(op string) string {
	c.t.Helper()
	c.id++
	msg := `<rpc xmlns="` + nsBase + `" message-id="` + itoa(c.id) + `">` + op + `</rpc>`
	if err := c.f.write([]byte(msg)); err != nil {
		c.t.Fatal(err)
	}
	reply, err := c.f.read()
	if err != nil {
		c.t.Fatal(err)
	}
	if !strings.Contains(string(reply), `message-id="`+itoa(c.id)+`"`) {
		c.t.Errorf("reply without its message-id: %s", reply)
	}
	return string(reply)
}

func (c *client) ok(op string) {
	c.t.Helper()
	if r := c.rpc(op); !strings.Contains(r, "<ok/>") {
		c.t.Fatalf("%s:\n%s", op, r)
	}
}

func (c *client) fails(op, tag string) string {
	c.t.Helper()
	r := c.rpc(op)
	if !strings.Contains(r, "<error-tag>"+tag+"</error-tag>") {
		c.t.Fatalf("%s: want %s:\n%s", op, tag, r)
	}
	return r
}

func itoa(n int) string { return strconv.Itoa(n) }

const cfg = `xmlns="urn:portitor:config"`

func edit(config string) string {
	return `<edit-config><target><candidate/></target><config>` + config + `</config></edit-config>`
}

func TestEditGetCommit(t *testing.T) {
	for _, base11 := range []bool{true, false} {
		env, m := newEnv()
		c := dial(t, env, base11)
		c.ok(edit(`<instance ` + cfg + `><name>host</name><is-default>true</is-default>
			<interface><name>wan0</name><kind>physical</kind><addresses>192.0.2.1/24</addresses><addresses>2001:db8::1/64</addresses></interface>
			<interface><name>lan0</name><mtu>9000</mtu><wg-private-key>MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=</wg-private-key></interface>
			</instance>`))
		r := c.rpc(`<get-config><source><candidate/></source><filter type="subtree"><instance ` + cfg + `><name>host</name><interface><name>wan0</name></interface></instance></filter></get-config>`)
		if !strings.Contains(r, "<addresses>2001:db8::1/64</addresses>") || strings.Contains(r, "lan0") {
			t.Errorf("filtered get-config:\n%s", r)
		}
		r = c.rpc(`<get-config><source><candidate/></source></get-config>`)
		if strings.Contains(r, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") || !strings.Contains(r, "<mtu>9000</mtu>") {
			t.Errorf("get-config:\n%s", r)
		}
		if r := c.rpc(`<get-config><source><running/></source></get-config>`); strings.Contains(r, "wan0") {
			t.Errorf("running before the commit: %s", r)
		}
		c.ok(`<commit/>`)
		if m.commits != 1 || m.pending {
			t.Errorf("commits %d, pending %v", m.commits, m.pending)
		}
		if r := c.rpc(`<get><filter type="subtree"><instance ` + cfg + `/></filter></get>`); !strings.Contains(r, "wan0") {
			t.Errorf("running after the commit: %s", r)
		}
		c.ok(`<close-session/>`)
	}
}

func TestOperations(t *testing.T) {
	env, _ := newEnv()
	c := dial(t, env, true)
	c.ok(edit(`<instance ` + cfg + `><name>host</name><interface><name>lan0</name><mtu>9000</mtu><wg-private-key>MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=</wg-private-key></interface></instance>`))
	c.fails(edit(`<instance `+cfg+`><name>host</name><interface xmlns:nc="`+nsBase+`" nc:operation="create"><name>lan0</name></interface></instance>`), "data-exists")
	c.fails(edit(`<instance `+cfg+`><name>host</name><vrf xmlns:nc="`+nsBase+`" nc:operation="delete"><name>red</name></vrf></instance>`), "data-missing")
	c.ok(edit(`<instance ` + cfg + `><name>host</name><vrf xmlns:nc="` + nsBase + `" nc:operation="remove"><name>red</name></vrf></instance>`))
	c.fails(edit(`<instance `+cfg+`><name>host</name><nonsense/></instance>`), "unknown-element")
	c.fails(edit(`<instance `+cfg+`><interface><name>x</name></interface></instance>`), "missing-element")
	c.fails(edit(`<instance `+cfg+`><name>host</name><interface><name>lan0</name><mtu>big</mtu></interface></instance>`), "invalid-value")
	// A replace without the secret keeps it.
	c.ok(edit(`<instance ` + cfg + `><name>host</name><interface xmlns:nc="` + nsBase + `" nc:operation="replace"><name>lan0</name><mtu>1500</mtu></interface></instance>`))
	cand, _ := env.Store.Candidate(context.Background())
	lan := cand.Root.Entry("instance", []string{"host"}).Entry("interface", []string{"lan0"})
	if lan.Leaves["mtu"] != "1500" || lan.Leaves["wg-private-key"] != "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" {
		t.Errorf("after replace: %v", lan.Leaves)
	}
	// Ordered entries go where yang:insert says.
	c.ok(edit(`<instance ` + cfg + `><name>host</name><rule><id>1</id><chain>input</chain></rule><rule><id>2</id><chain>input</chain></rule></instance>`))
	c.ok(edit(`<instance ` + cfg + ` xmlns:yang="` + nsYang + `"><name>host</name><rule yang:insert="before" yang:key="[id='1']"><id>3</id><chain>forward</chain></rule></instance>`))
	cand, _ = env.Store.Candidate(context.Background())
	var ids []string
	for _, r := range cand.Root.Entry("instance", []string{"host"}).Lists["rule"] {
		ids = append(ids, r.Leaves["id"])
	}
	if strings.Join(ids, " ") != "3 1 2" {
		t.Errorf("rule order %v", ids)
	}
	c.fails(`<edit-config><target><running/></target><config/></edit-config>`, "operation-not-supported")
	c.fails(`<kill-session><session-id>9</session-id></kill-session>`, "operation-not-supported")
	r := c.rpc(`<get-schema xmlns="` + nsMonitoring + `"><identifier>portitor-firewall</identifier><format>yang</format></get-schema>`)
	if !strings.Contains(r, "submodule portitor-firewall") {
		t.Errorf("get-schema: %.300s", r)
	}
	r = c.rpc(`<get><filter type="subtree"><netconf-state xmlns="` + nsMonitoring + `"><schemas/></netconf-state></filter></get>`)
	if !strings.Contains(r, "<identifier>portitor-routing</identifier>") {
		t.Errorf("schemas: %.300s", r)
	}
	// A rule without its chain: the candidate is not valid.
	c.ok(edit(`<instance ` + cfg + `><name>host</name><rule><id>9</id></rule></instance>`))
	if r := c.fails(`<validate><source><candidate/></source></validate>`, "invalid-value"); !strings.Contains(r, "chain") {
		t.Errorf("validate: %s", r)
	}
	c.fails(`<commit/>`, "invalid-value")
	c.ok(`<discard-changes/>`)
	c.ok(`<validate><source><candidate/></source></validate>`)
}

func TestLocksAndConfirmedCommit(t *testing.T) {
	env, m := newEnv()
	a := dial(t, env, true)
	b := dial(t, env, true)
	a.ok(`<lock><target><candidate/></target></lock>`)
	b.fails(`<lock><target><candidate/></target></lock>`, "lock-denied")
	b.fails(edit(`<instance `+cfg+`><name>host</name></instance>`), "lock-denied")
	// The CLI respects the lock too.
	if err := cli.RunScript(context.Background(), env, strings.NewReader("enter candidate\ninstance host description x\n"), &strings.Builder{}); err == nil {
		t.Error("the CLI edited a locked candidate")
	}
	a.ok(edit(`<instance ` + cfg + `><name>host</name><description>one</description></instance>`))
	a.ok(`<commit><confirmed/><confirm-timeout>60</confirm-timeout></commit>`)
	if !m.pending {
		t.Fatal("a confirmed commit doesn't wait")
	}
	a.ok(`<commit/>`) // confirms
	if m.pending || m.commits != 1 {
		t.Errorf("after the confirming commit: pending %v, commits %d", m.pending, m.commits)
	}
	a.ok(edit(`<instance ` + cfg + `><name>host</name><description>two</description></instance>`))
	a.ok(`<commit><confirmed/></commit>`)
	a.ok(`<cancel-commit/>`)
	if d := m.running.Root.Entry("instance", []string{"host"}).Leaves["description"]; d != "one" {
		t.Errorf("after cancel-commit: %q", d)
	}
	// The candidate keeps the cancelled change: b can't lock it until it
	// is discarded (RFC 6241 section 7.5).
	a.ok(`<unlock><target><candidate/></target></unlock>`)
	b.fails(`<lock><target><candidate/></target></lock>`, "lock-denied")
	b.ok(`<discard-changes/>`)
	b.ok(`<lock><target><candidate/></target></lock>`)
	// A session that ends lets its locks go.
	b.ok(`<close-session/>`)
	a.ok(`<lock><target><running/></target></lock>`)
}

func TestGetState(t *testing.T) {
	env, _ := newEnv()
	env.State = func(context.Context) (*datastore.Tree, error) {
		tr := datastore.New(env.Schema)
		sys := tr.Root.AddContainer(env.Schema.Child("system-state"))
		datastore.Fill(sys, map[string]any{"hostname": "fw1", "generation": 4, "host": map[string]any{"cpus": 2, "load": []float64{0.5, 0.25, 0.1}}})
		in := tr.Root.AddEntry(env.Schema.Child("instance"), map[string]string{"name": "host"})
		st := in.AddContainer(in.S.Child("state"))
		datastore.FillList(st, "interfaces", []map[string]any{{"name": "eth0", "state": "up", "rx_bytes": uint64(1) << 40}})
		return tr, nil
	}
	c := dial(t, env, true)
	r := c.rpc(`<get><filter type="subtree"><system-state ` + cfg + `/></filter></get>`)
	if !strings.Contains(r, "<hostname>fw1</hostname>") || !strings.Contains(r, "<load>0.25</load>") || strings.Contains(r, "eth0") {
		t.Errorf("get system-state:\n%s", r)
	}
	r = c.rpc(`<get><filter type="subtree"><instance ` + cfg + `><name>host</name><state><interfaces><name>eth0</name></interfaces></state></instance></filter></get>`)
	if !strings.Contains(r, "<rx-bytes>1099511627776</rx-bytes>") {
		t.Errorf("get interface state:\n%s", r)
	}
	c.fails(edit(`<system-state `+cfg+`><hostname>x</hostname></system-state>`), "invalid-value")
	if r := c.rpc(`<get-config><source><running/></source></get-config>`); strings.Contains(r, "fw1") {
		t.Errorf("state in get-config: %s", r)
	}
}
