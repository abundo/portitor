// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abundo/portitor/internal/datastore"
	"github.com/abundo/portitor/internal/schema"
)

// memory is a backend in memory: a commit is what runs.
type memory struct {
	current, running *datastore.Tree
	commits          int
}

func (m *memory) Initial(context.Context) (*datastore.Tree, error) { return m.current.Clone(), nil }
func (m *memory) Running(context.Context) (*datastore.Tree, error) { return m.running.Clone(), nil }
func (m *memory) Commit(_ context.Context, t *datastore.Tree, o datastore.CommitOptions) (string, error) {
	if o.Validate {
		return "valid", nil
	}
	m.current, m.running = t.Clone(), t.Clone()
	m.commits++
	return "committed", nil
}

type allowAll struct{}

func (allowAll) CanRead(datastore.Path) bool  { return true }
func (allowAll) CanWrite(datastore.Path) bool { return true }

func newTest(t *testing.T) (*Session, *bytes.Buffer, *memory) {
	t.Helper()
	root := schema.MustLoad()
	m := &memory{current: datastore.New(root), running: datastore.New(root)}
	env := &Env{Store: datastore.NewStore(root, m, ""), Schema: root, User: "admin", Access: allowAll{}}
	var out bytes.Buffer
	return NewSession(env, &out), &out, m
}

func run(t *testing.T, s *Session, lines ...string) {
	t.Helper()
	for _, l := range lines {
		if err := s.Exec(context.Background(), l); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
	}
}

func TestEditAndCommit(t *testing.T) {
	s, out, m := newTest(t)
	if err := s.Exec(context.Background(), "instance host interface wan0 mtu 1500"); err == nil {
		t.Error("a change in running mode")
	}
	run(t, s,
		"enter candidate",
		"instance host is-default true",
		"instance host interface wan0",
		"kind vlan",
		"vlan-id 7",
		"addresses [ 192.0.2.1/24 2001:db8::1/64 ]",
		"exit all",
		"/ instance host interface lan0 mtu 9000",
		"instance host interface lan0 addresses 10.0.0.1/24",
	)
	if got := s.Prompt(); got != "--{ candidate shared default }--[  ]--" {
		t.Errorf("prompt %q", got)
	}
	out.Reset()
	run(t, s, "diff")
	for _, want := range []string{"+     instance host {", "+         interface wan0 {", "+             vlan-id 7"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("diff lacks %q:\n%s", want, out.String())
		}
	}
	run(t, s, "commit now")
	if m.commits != 1 || s.candidate {
		t.Fatalf("commits %d, candidate mode %v", m.commits, s.candidate)
	}
	out.Reset()
	run(t, s, "info instance host interface wan0")
	if want := "kind vlan\nvlan-id 7\naddresses [ 192.0.2.1/24 2001:db8::1/64 ]\n"; out.String() != want {
		t.Errorf("info:\n%s", out.String())
	}
}

func TestPasteInfo(t *testing.T) {
	s, out, _ := newTest(t)
	run(t, s, "enter candidate",
		"instance host interface wan0 description \"the uplink\"",
		"instance host rule 7 chain input",
		"instance host rule 7 in-interfaces [ wan0 ]",
	)
	out.Reset()
	run(t, s, "info")
	text := out.String()
	// Into an empty candidate, the text makes the same configuration.
	s2, out2, _ := newTest(t)
	run(t, s2, "enter candidate")
	for _, l := range strings.Split(text, "\n") {
		run(t, s2, l)
	}
	run(t, s2, "info")
	if out2.String() != text {
		t.Errorf("pasted:\n%s\nwant:\n%s", out2.String(), text)
	}
	if len(s2.cwd) != 0 {
		t.Errorf("context after the paste: %v", s2.cwd)
	}
}

func TestRenameAndDelete(t *testing.T) {
	s, out, _ := newTest(t)
	run(t, s, "enter candidate",
		"instance host interface wan0 kind physical",
		"instance host route 1 destination default",
		"instance host route 1 interface wan0",
		"instance host interface wan0",
		"rename / instance host interface wan0 to uplink",
	)
	if s.cwd.CLI() != "instance host interface uplink" {
		t.Errorf("context %q", s.cwd.CLI())
	}
	out.Reset()
	run(t, s, "info / instance host route 1 interface")
	if out.String() != "interface uplink\n" {
		t.Errorf("route after rename: %q", out.String())
	}
	out.Reset()
	run(t, s, "delete / instance host interface uplink")
	if !strings.Contains(out.String(), "instance host route 1 interface") {
		t.Errorf("no warning: %q", out.String())
	}
	if err := s.Exec(context.Background(), "commit stay"); err == nil || !strings.Contains(err.Error(), "doesn't name a interface") {
		t.Errorf("commit of a dangling reference: %v", err)
	}
}

func TestSuggest(t *testing.T) {
	s, _, _ := newTest(t)
	run(t, s, "enter candidate", "instance host interface wan0 kind physical")
	ctx := context.Background()
	if line, _ := s.Complete(ctx, "instance host inter"); line != "instance host interface" {
		t.Errorf("complete: %q", line)
	}
	if line, _ := s.Complete(ctx, "instance host interface w"); line != "instance host interface wan0 " {
		t.Errorf("complete key: %q", line)
	}
	if line, _ := s.Complete(ctx, "instance host interface wan0 ki"); line != "instance host interface wan0 kind " {
		t.Errorf("complete leaf: %q", line)
	}
	_, items := s.Suggest(ctx, "instance host interface wan0 kind ")
	var words []string
	for _, it := range items {
		words = append(words, it.Word)
	}
	if !strings.Contains(strings.Join(words, " "), "physical vlan bridge") {
		t.Errorf("kind values: %v", words)
	}
	_, items = s.Suggest(ctx, "instance host route 1 interface ")
	found := false
	for _, it := range items {
		found = found || it.Word == "wan0"
	}
	if !found {
		t.Errorf("leafref values: %v", items)
	}
	if line, _ := s.Complete(ctx, "comm"); line != "commit " {
		t.Errorf("command: %q", line)
	}
}

func TestScript(t *testing.T) {
	root := schema.MustLoad()
	m := &memory{current: datastore.New(root), running: datastore.New(root)}
	env := &Env{Store: datastore.NewStore(root, m, ""), Schema: root, User: "admin", Access: allowAll{}}
	var out bytes.Buffer
	err := RunScript(context.Background(), env, strings.NewReader(splitCommands(`enter candidate; instance host description "a; b"; commit now`)), &out)
	if err != nil || m.commits != 1 {
		t.Fatalf("script: %v (%d commits)", err, m.commits)
	}
	if got := m.running.Root.Entry("instance", []string{"host"}).Leaves["description"]; got != "a; b" {
		t.Errorf("description %q", got)
	}
}

func TestSSH(t *testing.T) {
	root := schema.MustLoad()
	m := &memory{current: datastore.New(root), running: datastore.New(root)}
	env := &Env{Store: datastore.NewStore(root, m, ""), Schema: root, User: "admin", Access: allowAll{}}
	key, err := LoadHostKey(t.TempDir() + "/key")
	if err != nil {
		t.Fatal(err)
	}
	srv := &SSHServer{HostKey: key, Login: func(_ context.Context, _ net.Addr, user, pw, code string) (*Env, bool, error) {
		if user != "admin" || pw != "pw" {
			return nil, false, errors.New("wrong")
		}
		if code == "" {
			return nil, true, nil
		}
		if code != "123456" {
			return nil, false, errors.New("wrong code")
		}
		return env, false, nil
	}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.serve(ctx, ln, srv.config(ctx))
	dial := func(code string) (*ssh.Client, error) {
		return ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
			User:            "admin",
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Auth: []ssh.AuthMethod{ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				if strings.HasPrefix(qs[0], "Password") {
					return []string{"pw"}, nil
				}
				return []string{code}, nil
			})},
		})
	}
	if _, err := dial("000000"); err == nil {
		t.Fatal("a wrong code logged in")
	}
	c, err := dial("123456")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.CombinedOutput("enter candidate; instance host description ssh; commit now; info instance host")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(string(out), "description ssh") || m.commits != 1 {
		t.Errorf("exec: %s", out)
	}
}

// pipeRW is a terminal's two ends in memory.
type pipeRW struct {
	io.Reader
	io.Writer
}

func TestTerminal(t *testing.T) {
	root := schema.MustLoad()
	m := &memory{current: datastore.New(root), running: datastore.New(root)}
	env := &Env{Store: datastore.NewStore(root, m, ""), Schema: root, User: "admin", Access: allowAll{}}
	in, keys := io.Pipe()
	var out syncBuffer
	tm := NewTerminal(env, pipeRW{in, &out})
	done := make(chan error, 1)
	go func() { done <- tm.Run(context.Background()) }()
	// Tab completes "ente" to "enter ", ? lists the modes, then the line runs.
	for _, k := range []string{"ente\t", "?", "candidate\r", "inst\t", "host description x\r", "exit\r"} {
		if _, err := keys.Write([]byte(k)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	keys.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the terminal hangs")
	}
	got := out.String()
	for _, want := range []string{"enter ", "edit the shared candidate", "candidate shared default", "instance "} {
		if !strings.Contains(got, want) {
			t.Errorf("terminal output lacks %q:\n%s", want, got)
		}
	}
	if m.current.Root.Entry("instance", []string{"host"}) != nil {
		t.Error("an uncommitted edit reached the configuration")
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
