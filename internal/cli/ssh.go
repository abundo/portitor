// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSHServer serves the CLI over SSH to portitor-config's users: their
// password (a directory user's at the directory), then the code of their
// two-factor login when they have one.
type SSHServer struct {
	Addr    string
	HostKey ssh.Signer
	// Login checks a login from addr and returns the user's session. With
	// needCode, the password is right and a two-factor code is wanted.
	Login func(ctx context.Context, addr net.Addr, user, password, code string) (env *Env, needCode bool, err error)
	// Subsystems serve SSH subsystems by name (netconf).
	Subsystems map[string]func(ctx context.Context, env *Env, rw io.ReadWriter) error

	envs sync.Map // session id → *Env, from the login to the session
}

// LoadHostKey reads the SSH host key at path, making an Ed25519 one when
// there is none.
func LoadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, gerr
		}
		block, merr := ssh.MarshalPrivateKey(priv, "portitor-config")
		if merr != nil {
			return nil, merr
		}
		data = pem.EncodeToMemory(block)
		if werr := os.WriteFile(path, data, 0o600); werr != nil {
			return nil, werr
		}
	} else if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}

// Serve accepts connections until ctx is cancelled.
func (srv *SSHServer) Serve(ctx context.Context) error {
	cfg := srv.config(ctx)
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	slog.Info("CLI listening (SSH)", "addr", ln.Addr())
	return srv.serve(ctx, ln, cfg)
}

// ServeListener is Serve on a listener of the caller's.
func (srv *SSHServer) ServeListener(ctx context.Context, ln net.Listener) error {
	return srv.serve(ctx, ln, srv.config(ctx))
}

func (srv *SSHServer) config(ctx context.Context) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-portitor",
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			env, needCode, err := srv.Login(ctx, c.RemoteAddr(), c.User(), string(pw), "")
			if err != nil {
				return nil, err
			}
			if needCode {
				return nil, errors.New("two-factor login: use keyboard-interactive authentication")
			}
			srv.envs.Store(string(c.SessionID()), env)
			return &ssh.Permissions{}, nil
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ask("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(ans) != 1 {
				return nil, errors.New("no password")
			}
			env, needCode, err := srv.Login(ctx, c.RemoteAddr(), c.User(), ans[0], "")
			if err != nil {
				return nil, err
			}
			if needCode {
				code, err := ask("", "Two-factor login", []string{"Code from your authenticator app (or a recovery code): "}, []bool{true})
				if err != nil || len(code) != 1 {
					return nil, errors.New("no code")
				}
				if env, _, err = srv.Login(ctx, c.RemoteAddr(), c.User(), ans[0], code[0]); err != nil {
					return nil, err
				}
			}
			srv.envs.Store(string(c.SessionID()), env)
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(srv.HostKey)
	return cfg
}

func (srv *SSHServer) serve(ctx context.Context, ln net.Listener, cfg *ssh.ServerConfig) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go srv.handle(ctx, conn, cfg)
	}
}

func (srv *SSHServer) handle(ctx context.Context, conn net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sc.Close()
	v, ok := srv.envs.LoadAndDelete(string(sc.SessionID()))
	if !ok {
		return
	}
	env := v.(*Env)
	slog.Info("CLI login", "user", sc.User(), "from", sc.RemoteAddr())
	go ssh.DiscardRequests(reqs)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go srv.session(ctx, env, ch, creqs)
	}
}

func (srv *SSHServer) session(ctx context.Context, env *Env, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	var tm *Terminal
	var pty bool
	var width, height uint32
	exit := func(err error) {
		code := uint32(0)
		if err != nil {
			fmt.Fprintf(ch.Stderr(), "Error: %v\n", err)
			code = 1
		}
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, code)
		ch.SendRequest("exit-status", false, status)
	}
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			pty = true
			width, height = ptySize(req.Payload)
			req.Reply(true, nil)
		case "window-change":
			if len(req.Payload) >= 8 {
				width, height = binary.BigEndian.Uint32(req.Payload), binary.BigEndian.Uint32(req.Payload[4:])
				if tm != nil {
					tm.SetSize(int(width), int(height))
				}
			}
			req.Reply(true, nil)
		case "env":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			if !pty {
				exit(RunScript(ctx, env, ch, ch))
				return
			}
			tm = NewTerminal(env, ch)
			if width > 0 {
				tm.SetSize(int(width), int(height))
			}
			go func() {
				exit(tm.Run(ctx))
				ch.Close()
			}()
		case "exec":
			req.Reply(true, nil)
			cmd := ""
			if len(req.Payload) >= 4 {
				n := binary.BigEndian.Uint32(req.Payload)
				if int(n) <= len(req.Payload)-4 {
					cmd = string(req.Payload[4 : 4+n])
				}
			}
			exit(RunScript(ctx, env, strings.NewReader(splitCommands(cmd)), ch))
			return
		case "subsystem":
			name := ""
			if len(req.Payload) >= 4 {
				if n := binary.BigEndian.Uint32(req.Payload); int(n) <= len(req.Payload)-4 {
					name = string(req.Payload[4 : 4+n])
				}
			}
			serve := srv.Subsystems[name]
			req.Reply(serve != nil, nil)
			if serve == nil {
				continue
			}
			err := serve(ctx, env, ch)
			if err != nil {
				slog.Warn("SSH subsystem", "name", name, "user", env.User, "err", err)
			}
			exit(nil)
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func ptySize(p []byte) (uint32, uint32) {
	if len(p) < 4 {
		return 0, 0
	}
	n := binary.BigEndian.Uint32(p)
	if int(n)+12 > len(p) {
		return 0, 0
	}
	p = p[4+n:]
	return binary.BigEndian.Uint32(p), binary.BigEndian.Uint32(p[4:])
}

// splitCommands puts each command of an exec on a line of its own: they
// are separated by newlines, or by ; outside quotes.
func splitCommands(cmd string) string {
	var b strings.Builder
	var quote rune
	for _, r := range cmd {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ';':
			b.WriteByte('\n')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
