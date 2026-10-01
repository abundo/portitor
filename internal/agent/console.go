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
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"

	"github.com/abundo/portitor/internal/agentapi"
	"github.com/abundo/portitor/internal/fwconfig"
)

// ConsoleDisabled as console_user turns the console off.
const ConsoleDisabled = "none"

// handleConsole runs a login shell as cfg.ConsoleUser on a pseudo-terminal
// and connects it to a WebSocket (protocol in agentapi.ConsoleResize). With
// ?instance=, the shell runs in that applied instance's network namespace.
func (a *Agent) handleConsole(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ConsoleUser == ConsoleDisabled {
		writeError(w, http.StatusNotFound, errors.New("the console is disabled (console_user: none)"))
		return
	}
	var netnsName string
	if name := r.URL.Query().Get("instance"); name != "" {
		a.mu.Lock()
		var in *fwconfig.Instance
		if a.applied != nil {
			d := a.applied.Expand()
			in = d.Instance(name)
		}
		a.mu.Unlock()
		if in == nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("no applied instance %q", name))
			return
		}
		netnsName = in.NetnsName()
	}
	cmd, err := consoleCommand(a.cfg.ConsoleUser, a.cfg.DryRun)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	// The server's read/write timeouts are for requests, not a session.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		slog.Warn("console: websocket", "err", err)
		return
	}
	defer conn.CloseNow()
	conn.SetReadLimit(1 << 20)

	// The shell inherits the namespace of the thread that starts it.
	var ptmx *os.File
	err = withNetns(netnsName, func() (err error) {
		ptmx, err = pty.Start(cmd)
		return err
	})
	if err != nil {
		slog.Error("console: start shell", "user", a.cfg.ConsoleUser, "err", err)
		conn.Close(websocket.StatusInternalError, truncateReason("start shell: "+err.Error()))
		return
	}
	slog.Info("console: session started", "user", a.cfg.ConsoleUser, "netns", netnsName, "remote", r.RemoteAddr, "pid", cmd.Process.Pid)
	defer func() {
		ptmx.Close() // hangs up the session
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		slog.Info("console: session ended", "user", a.cfg.ConsoleUser, "remote", r.RemoteAddr)
	}()

	ctx := context.Background()
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if conn.Write(ctx, websocket.MessageBinary, buf[:n]) != nil {
					return
				}
			}
			if err != nil {
				// The shell exited (EIO on the master).
				conn.Close(websocket.StatusNormalClosure, "session ended")
				return
			}
		}
	}()
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		switch typ {
		case websocket.MessageBinary:
			if _, err := ptmx.Write(data); err != nil {
				return
			}
		case websocket.MessageText:
			var rs agentapi.ConsoleResize
			if json.Unmarshal(data, &rs) == nil && rs.Cols > 0 && rs.Rows > 0 && rs.Cols <= 1000 && rs.Rows <= 1000 {
				_ = pty.Setsize(ptmx, &pty.Winsize{Cols: rs.Cols, Rows: rs.Rows})
			}
		}
	}
}

// consoleCommand is a login shell for the named user. Only root can switch
// user; a non-root agent in dry-run mode (development) runs the shell as
// itself instead.
func consoleCommand(name string, dryRun bool) (*exec.Cmd, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("console user: %w", err)
	}
	var cred *syscall.Credential
	if os.Geteuid() == 0 {
		cred, err = credential(u)
		if err != nil {
			return nil, err
		}
	} else if u.Uid != strconv.Itoa(os.Getuid()) {
		if !dryRun {
			return nil, fmt.Errorf("the agent is not running as root, so it cannot start a shell as %s", name)
		}
		if u, err = user.Current(); err != nil {
			return nil, err
		}
	}
	shell, err := loginShell("/etc/passwd", u.Username)
	if err != nil {
		return nil, err
	}
	dir := u.HomeDir
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		dir = "/"
	}
	cmd := exec.Command(shell)
	cmd.Args = []string{"-" + filepath.Base(shell)} // a login shell
	cmd.Dir = dir
	cmd.Env = []string{
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"LOGNAME=" + u.Username,
		"SHELL=" + shell,
		"TERM=xterm-256color",
		"LANG=C.UTF-8",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if cred != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	return cmd, nil
}

func credential(u *user.User) (*syscall.Credential, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	c := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	ids, _ := u.GroupIds()
	for _, s := range ids {
		if g, err := strconv.ParseUint(s, 10, 32); err == nil {
			c.Groups = append(c.Groups, uint32(g))
		}
	}
	return c, nil
}

// loginShell reads the user's shell from passwd, refusing accounts that
// cannot log in.
func loginShell(passwd, name string) (string, error) {
	f, err := os.Open(passwd)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) != 7 || fields[0] != name {
			continue
		}
		shell := fields[6]
		if shell == "" {
			shell = "/bin/sh"
		}
		switch filepath.Base(shell) {
		case "nologin", "false":
			return "", fmt.Errorf("user %s has no login shell (%s)", name, shell)
		}
		return shell, nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("user %s is not in %s", name, passwd)
}

// truncateReason fits a WebSocket close reason (at most 123 bytes).
func truncateReason(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
