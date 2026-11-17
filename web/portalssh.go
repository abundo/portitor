// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/abundo/portitor/internal/buildinfo"
)

// PortalInfo is what `portitor-config portal-info` prints on a firewall: what
// portitor-manager needs to serve its GUI.
type PortalInfo struct {
	// Port is the port of portitor-config's bind address.
	Port int `json:"port"`
	// TLS is false when portitor-config serves plain HTTP.
	TLS bool `json:"tls"`
	// Fingerprint is the SHA-256 of tls_cert.
	Fingerprint string `json:"fingerprint,omitempty"`
	Version     string `json:"version"`
}

// SSHProbe is a request to read PortalInfo over SSH. The credentials are
// used for this one connection and never kept.
type SSHProbe struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	User       string `json:"user"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	// HostKey is the SSH host key (SHA256:...) the administrator confirmed;
	// empty asks for it, and nothing is sent before it is confirmed.
	HostKey string `json:"host_key"`
}

// SSHProbeResult is its answer: either the host key to confirm, or what the
// firewall said.
type SSHProbeResult struct {
	HostKey string      `json:"host_key"`
	Confirm bool        `json:"confirm,omitempty"`
	Info    *PortalInfo `json:"info,omitempty"`
	URL     string      `json:"url,omitempty"`
}

var errHostKeyUnconfirmed = errors.New("host key not confirmed")

// configCommand runs a portitor-config command on the firewall: as root
// directly, otherwise as the service user through sudo.
func configCommand(user string, args ...string) string {
	cmd := "portitor-config " + strings.Join(args, " ")
	if user == "root" || user == "portitor" {
		return cmd
	}
	return "sudo -n -u portitor " + cmd
}

// sshConn is a logged-in SSH connection to a firewall, to run the fixed
// portitor-config commands the portal needs.
type sshConn struct {
	client *ssh.Client
	user   string
	host   string
	// Remote is the address the connection reached.
	Remote netip.Addr
}

func (c *sshConn) Close() { _ = c.client.Close() }

// run runs a command with stdin, and returns its standard output. The
// error holds its standard error, which no command prints a secret to.
func (c *sshConn) run(cmd string, stdin []byte) ([]byte, error) {
	sess, err := c.client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var out, errOut bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &errOut
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	if err := sess.Run(cmd); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return out.Bytes(), nil
}

// dialSSH connects to the host, checking its host key against p.HostKey
// (empty asks for it: the result then has Confirm and the key, and no
// connection) and logging in.
func dialSSH(ctx context.Context, p SSHProbe) (*sshConn, *SSHProbeResult, error) {
	if p.Host == "" || p.User == "" {
		return nil, nil, errors.New("host and user are needed")
	}
	if p.Port == 0 {
		p.Port = 22
	}
	var methods []ssh.AuthMethod
	if p.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(p.PrivateKey))
		if err != nil {
			return nil, nil, fmt.Errorf("private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if p.Password != "" {
		methods = append(methods, ssh.Password(p.Password))
	}
	res := &SSHProbeResult{}
	cfg := &ssh.ClientConfig{
		User: p.User,
		Auth: methods,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			res.HostKey = ssh.FingerprintSHA256(key)
			if p.HostKey == "" || p.HostKey != res.HostKey {
				res.Confirm = true
				return errHostKeyUnconfirmed
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		if res.Confirm {
			if p.HostKey != "" {
				return nil, nil, fmt.Errorf("the host key is %s, not the confirmed %s", res.HostKey, p.HostKey)
			}
			return nil, res, nil
		}
		return nil, nil, fmt.Errorf("ssh: %w", err)
	}
	c := &sshConn{client: ssh.NewClient(cc, chans, reqs), user: p.User, host: p.Host}
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		c.Remote, _ = netip.AddrFromSlice(ta.IP)
		c.Remote = c.Remote.Unmap()
	}
	return c, res, nil
}

// RunSSHProbe connects to the host, checks (or asks for) its host key,
// logs in and runs portitor-config portal-info.
func RunSSHProbe(ctx context.Context, p SSHProbe) (*SSHProbeResult, error) {
	c, res, err := dialSSH(ctx, p)
	if err != nil || c == nil {
		return res, err
	}
	defer c.Close()
	out, err := c.run(configCommand(p.User, "portal-info"), nil)
	if err != nil {
		return nil, fmt.Errorf("portitor-config portal-info on %s: %w", p.Host, err)
	}
	var info PortalInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("portitor-config portal-info: unexpected answer: %w", err)
	}
	scheme := "https"
	if !info.TLS {
		scheme = "http"
	}
	res.Info = &info
	res.URL = scheme + "://" + net.JoinHostPort(p.Host, strconv.Itoa(info.Port))
	return res, nil
}

// ReadPortalInfo is `portitor-config portal-info`: the port of the bind
// address and tls_cert's fingerprint.
func ReadPortalInfo(cfg *Config) (*PortalInfo, error) {
	_, port, err := net.SplitHostPort(cfg.Bind)
	if err != nil {
		return nil, fmt.Errorf("bind %q: %w", cfg.Bind, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bind %q: no port", cfg.Bind)
	}
	info := &PortalInfo{Port: n, TLS: cfg.TLSCert != "", Version: buildinfo.Version}
	if info.TLS {
		if info.Fingerprint, err = CertFingerprint(cfg.TLSCert); err != nil {
			return nil, err
		}
	}
	return info, nil
}
