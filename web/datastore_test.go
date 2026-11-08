// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/abundo/portitor/internal/builder"
	"github.com/abundo/portitor/internal/cli"
	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/netconf"
	"github.com/abundo/portitor/internal/schema"
	"github.com/abundo/portitor/models"
)

func cliScript(t *testing.T, env *cli.Env, script string) string {
	t.Helper()
	var out bytes.Buffer
	if err := cli.RunScript(context.Background(), env, strings.NewReader(script), &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	return out.String()
}

func TestCLICommit(t *testing.T) {
	env, _ := consoleEnv(t, "")
	ctx := context.Background()
	cenv, err := env.srv.ConsoleCLI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var host models.Instance
	if err := env.srv.db.Where("is_default = ?", true).First(&host).Error; err != nil {
		t.Fatal(err)
	}
	out := cliScript(t, cenv, `enter candidate
instance `+host.Name+` interface lo1 kind loopback
instance `+host.Name+` interface lo1 addresses [ 10.99.0.1/32 ]
commit now
`)
	if !strings.Contains(out, "Commit 1: applied.") {
		t.Errorf("commit: %s", out)
	}
	var dep models.Deployment
	env.srv.db.Order("id desc").First(&dep)
	if dep.Status != "applied" || dep.Username != "console" {
		t.Errorf("deployment %+v", dep)
	}
	run, err := cenv.Store.Running(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if run.Root.Entry("instance", []string{host.Name}).Entry("interface", []string{"lo1"}) == nil {
		t.Error("running lacks lo1")
	}

	// An edit in the CLI, then one in the GUI: the commit has both.
	cliScript(t, cenv, "enter candidate\ninstance "+host.Name+" interface lo1 description cli\n")
	env.put("instance="+host.Name+"/interface=lo2", map[string]any{"kind": "loopback", "enabled": true, "ipv4-mode": "static"})
	out = cliScript(t, cenv, "enter candidate\ndiff flat\ncommit stay\n")
	if strings.Contains(out, "pending") {
		cliScript(t, cenv, "confirm\n")
	}
	if !strings.Contains(out, "interface lo1 description cli") || !strings.Contains(out, "interface lo2") {
		t.Errorf("diff: %s", out)
	}
	run, err = cenv.Store.Running(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := run.Root.Entry("instance", []string{host.Name})
	if h.Entry("interface", []string{"lo1"}).Leaves["description"] != "cli" || h.Entry("interface", []string{"lo2"}) == nil {
		t.Errorf("after commit: %v", h.Lists["interface"])
	}

	// A commit that fails leaves running as it was, and the candidate.
	before, _ := cenv.Store.Running(ctx)
	var bad bytes.Buffer
	err = cli.RunScript(ctx, cenv, strings.NewReader("enter candidate\ninstance "+host.Name+" interface vl9 kind vlan\ncommit stay\n"), &bad)
	if err == nil {
		t.Fatalf("a VLAN without a parent committed: %s", bad.String())
	}
	if after, _ := cenv.Store.Running(ctx); !datastore.Equal(before, after) {
		t.Error("running changed after a failed commit")
	}
	if changed, _ := cenv.Store.Changed(ctx); !changed {
		t.Error("the failed commit lost the candidate")
	}
}

func TestCLIAccess(t *testing.T) {
	env := newEnv(t)
	if err := CreateUser(env.srv, "viewer", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	env.srv.db.Model(&models.User{}).Where("username = ?", "viewer").Update("role", models.RoleViewer)
	var u models.User
	env.srv.db.Where("username = ?", "viewer").First(&u)
	cenv, err := env.srv.cliEnv(context.Background(), &u)
	if err != nil {
		t.Fatal(err)
	}
	if cenv.ReadOnly == "" {
		t.Error("a viewer may enter candidate")
	}
	if cenv.Access.CanWrite(datastore.Path{{Name: "host", Keys: []string{"x"}}}) {
		t.Error("a viewer may write")
	}
	if _, _, err := env.srv.cliLogin(context.Background(), fakeAddr("192.0.2.1:22"), "viewer", "wrong", ""); err == nil {
		t.Error("a wrong password logged in")
	}
	if e, need, err := env.srv.cliLogin(context.Background(), fakeAddr("192.0.2.1:22"), "viewer", "correct horse battery", ""); err != nil || need || e.User != "viewer" {
		t.Errorf("login: %v %v %v", e, need, err)
	}
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// TestNETCONFOverSSH runs a NETCONF session through the SSH server, as
// the web's users, to a commit deployed by the dry-run agent.
func TestNETCONFOverSSH(t *testing.T) {
	env, _ := consoleEnv(t, "")
	if err := env.srv.ensureDefaultInstance(); err != nil {
		t.Fatal(err)
	}
	var host models.Instance
	env.srv.db.Where("is_default = ?", true).First(&host)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	env.srv.cfg.SSHListen = "127.0.0.1:0"
	env.srv.cfg.DB.Path = filepath.Join(dir, "db.sqlite")
	key, err := cli.LoadHostKey(filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	srv := &cli.SSHServer{HostKey: key, Login: env.srv.cliLogin,
		Subsystems: map[string]func(context.Context, *cli.Env, io.ReadWriter) error{"netconf": netconf.Serve}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeListener(ctx, ln)
	c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "admin", HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{ssh.Password("correct horse battery")}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.RequestSubsystem("netconf"); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		var b []byte
		buf := make([]byte, 4096)
		for !bytes.HasSuffix(b, []byte("]]>]]>")) {
			n, err := out.Read(buf)
			if err != nil {
				t.Fatalf("read: %v (%s)", err, b)
			}
			b = append(b, buf[:n]...)
		}
		return string(b)
	}
	send := func(msg string) string {
		io.WriteString(in, msg+"]]>]]>")
		return read()
	}
	read() // hello
	io.WriteString(in, `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>`)
	r := send(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><edit-config><target><candidate/></target><config>` +
		`<instance xmlns="urn:portitor:config"><name>` + host.Name + `</name><interface><name>lo7</name><kind>loopback</kind><addresses>10.77.0.1/32</addresses></interface></instance>` +
		`</config></edit-config></rpc>`)
	if !strings.Contains(r, "<ok/>") {
		t.Fatalf("edit-config: %s", r)
	}
	if r := send(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2"><commit/></rpc>`); !strings.Contains(r, "<ok/>") {
		t.Fatalf("commit: %s", r)
	}
	if !strings.Contains(r, "<ok/>") {
		t.Fatal(r)
	}
	var dep models.Deployment
	env.srv.db.Order("id desc").First(&dep)
	if dep.Username != "admin" || dep.Status != "applied" {
		t.Errorf("deployment %+v", dep)
	}
}

func TestCLIState(t *testing.T) {
	env, _ := consoleEnv(t, "")
	ctx := context.Background()
	cenv, err := env.srv.ConsoleCLI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var host models.Instance
	env.srv.db.Where("is_default = ?", true).First(&host)
	cliScript(t, cenv, "enter candidate\ninstance "+host.Name+" interface lo1 kind loopback\ninstance "+host.Name+" rule 77 chain input\n"+
		"instance "+host.Name+" ntp-enabled true\ninstance "+host.Name+" ntp-server pool.ntp.org pool true\n"+
		"instance "+host.Name+" interface br0 kind bridge\ninstance "+host.Name+" interface br0 addresses [ 10.99.0.1/24 ]\n"+
		"instance "+host.Name+" vrrp-router br0 7 ipv4 [ 10.99.0.9 ]\ncommit now\n")
	out := cliScript(t, cenv, "info from state / system-state\ninfo from state / instance "+host.Name+" state\n")
	t.Log(out)
	for _, want := range []string{"dry-run true", "generation 1", "ntp {", "vrrp {", `rate-limits "dns server" {`} {
		if !strings.Contains(out, want) {
			t.Errorf("state lacks %q:\n%s", want, out)
		}
	}
	if err := cli.RunScript(ctx, cenv, strings.NewReader("enter candidate\n/ system-state hostname x\n"), &bytes.Buffer{}); err == nil {
		t.Error("state was set")
	}
}

// tablesInput is the builder's input from the tables a test wrote.
func tablesInput(t *testing.T, db *gorm.DB) builder.Input {
	t.Helper()
	tree, _, err := tablesTree(db)
	if err != nil {
		t.Fatal(err)
	}
	if tree == nil {
		root, _ := schema.Load()
		tree = datastore.New(root)
	}
	return builder.Input{DB: db, Tree: tree}
}

// A virtual firewall renamed in the CLI keeps its role and members; one
// made there gets its role.
func TestCLIInstanceRoles(t *testing.T) {
	env, _ := consoleEnv(t, "")
	ctx := context.Background()
	cenv, err := env.srv.ConsoleCLI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	env.vf("lab")
	ann := env.create("/api/users", map[string]string{"username": "ann", "password": "a long password", "role": "none"})
	r := env.roles()["vf-lab"]
	env.do("PUT", "/api/roles/"+itoa(r.ID), map[string]any{"members": []map[string]any{{"user_id": ann, "level": "admin"}}})
	ops := env.create("/api/roles", map[string]any{"name": "ops", "instances": []string{"lab"}})

	cliScript(t, cenv, "enter candidate\nrename instance lab to lab2\n")
	roles := env.roles()
	if got := roles["vf-lab2"]; got.ID != r.ID || len(got.Members) != 1 || got.Instance == nil || *got.Instance != "lab2" {
		t.Errorf("renamed: %+v", roles)
	}
	if g := roles["ops"].Instances; len(g) != 1 || g[0] != "lab2" || roles["ops"].ID != ops {
		t.Errorf("grant: %v", g)
	}

	var host models.Instance
	env.srv.db.Where("is_default = ?", true).First(&host)
	var fw models.Firewall
	env.srv.db.First(&fw)
	cliScript(t, cenv, "enter candidate\ninstance shop firewall "+fw.Name+"\n")
	if _, ok := env.roles()["vf-shop"]; !ok {
		t.Errorf("no role for a virtual firewall made in the CLI: %v", env.roles())
	}
}
