// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"net/url"
	"regexp"
	"slices"
)

// HA nodes.
const (
	HAPrimary   = "primary"
	HASecondary = "secondary"
)

// HA makes the document's host one of an HA pair. Both hosts apply the
// same instances (the secondary with its own addresses); VRRP decides
// which one forwards. A host may be active only with a quorum: it hears
// its peer, or it holds the witness's vote (portitor-web). Without one it
// is fenced: its VRRP routers are shut down and it serves no DHCP or
// router advertisements, so the two never both answer for the virtual
// addresses.
type HA struct {
	Node string `json:"node"`
	// Peer is the other host's agent API (https://...), its certificate
	// pinned by PeerFingerprint (SHA-256, hex).
	Peer            string `json:"peer"`
	PeerFingerprint string `json:"peer_fingerprint"`
	// Secret is shared by the pair for the heartbeat (/v1/ha/heartbeat)
	// and the copy of the certificates; the secondary's portitor-config
	// copies the primary's database with it too.
	Secret string `json:"secret"`
	// WitnessSecret, when the pair's witness is external (portitor-web on
	// a third host), opens GET /v1/ha and POST /v1/ha/vote to it alone.
	WitnessSecret string `json:"witness_secret,omitempty"`
	// PeerConfig is the peer's portitor-config (https://...), its tls_cert
	// pinned by PeerConfigFingerprint: where the secondary's
	// portitor-config copies the configuration from. Empty: none.
	PeerConfig            string `json:"peer_config,omitempty"`
	PeerConfigFingerprint string `json:"peer_config_fingerprint,omitempty"`
	// Epoch counts the pair's promotions: a secondary promoted to primary
	// raises it. A primary that hears a peer that is primary at a higher
	// epoch has been taken over: it is stale, fenced and standby, until it
	// is given the document of the secondary it now is.
	Epoch int64 `json:"epoch,omitempty"`
	// ConfigPort is this host's portitor-config port (its own
	// portitor-config URL's), which the default instance opens to the
	// peer's addresses (HAConfigAccess): the secondary copies the
	// configuration from the primary, and the other way round once it is
	// promoted. 0: none.
	ConfigPort int `json:"config_port,omitempty"`
}

// HAConfigAccess is what Expand gives an HA host's default instance from
// HA: its portitor-config's port, opened to the peer's addresses (the auto
// rule render.HAConfigService).
type HAConfigAccess struct {
	Port int
	From []string
}

// configAccess: the peer's addresses are those written as addresses in
// its agent and portitor-config URLs; a name gives none.
func (h *HA) configAccess() *HAConfigAccess {
	if h == nil || h.ConfigPort == 0 {
		return nil
	}
	var from []string
	for _, s := range []string{h.Peer, h.PeerConfig} {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		if a, err := netip.ParseAddr(u.Hostname()); err == nil && !slices.Contains(from, a.Unmap().String()) {
			from = append(from, a.Unmap().String())
		}
	}
	if len(from) == 0 {
		return nil
	}
	return &HAConfigAccess{Port: h.ConfigPort, From: from}
}

var (
	haFingerprintRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	haSecretRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

func (v *validator) ha(h *HA) {
	if h == nil {
		return
	}
	if h.Node != HAPrimary && h.Node != HASecondary {
		v.addf("ha: node must be %s or %s", HAPrimary, HASecondary)
	}
	if u, err := url.Parse(h.Peer); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		v.addf("ha: peer must be the other host's agent URL (https://<address>:8443)")
	}
	if !haFingerprintRe.MatchString(h.PeerFingerprint) {
		v.addf("ha: peer fingerprint must be 64 lowercase hex characters")
	}
	if !haSecretRe.MatchString(h.Secret) {
		v.addf("ha: secret must be 32-128 URL-safe base64 characters")
	}
	if h.WitnessSecret != "" && (!haSecretRe.MatchString(h.WitnessSecret) || h.WitnessSecret == h.Secret) {
		v.addf("ha: witness secret must be 32-128 URL-safe base64 characters, not the pair's secret")
	}
	if h.PeerConfig != "" {
		if u, err := url.Parse(h.PeerConfig); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			v.addf("ha: peer config must be the other host's portitor-config URL (https://<address>:<port>)")
		}
		if !haFingerprintRe.MatchString(h.PeerConfigFingerprint) {
			v.addf("ha: peer config fingerprint must be 64 lowercase hex characters")
		}
	}
	if h.Epoch < 0 {
		v.addf("ha: epoch must not be negative")
	}
	if h.ConfigPort < 0 || h.ConfigPort > 65535 {
		v.addf("ha: config port must be 1-65535")
	}
}

// Kea's HA roles.
const (
	DHCPHAPrimary = "primary"
	DHCPHAStandby = "standby"
)

// DHCPHA runs Kea's HA hook in hot-standby between the two hosts of an HA
// pair: the primary serves and keeps the standby's leases in step; the
// standby serves when the primary stops answering. They talk HTTP on
// Interface, from This to Peer (IPv4 addresses on it), on
// render.KeaHAPort4 and KeaHAPort6, which the auto rules open to Peer
// alone.
type DHCPHA struct {
	Role      string `json:"role"`
	Interface string `json:"interface"`
	This      string `json:"this"`
	Peer      string `json:"peer"`
}

func (v *validator) dhcpHA(p string, in *Instance) {
	h := in.DHCP.HA
	if h == nil {
		return
	}
	if h.Role != DHCPHAPrimary && h.Role != DHCPHAStandby {
		v.addf("%s: dhcp ha: role must be %s or %s", p, DHCPHAPrimary, DHCPHAStandby)
	}
	if !ValidIfname(h.Interface) {
		v.addf("%s: dhcp ha: invalid interface %q", p, h.Interface)
	}
	for _, a := range []string{h.This, h.Peer} {
		if ip, err := netip.ParseAddr(a); err != nil || !ip.Is4() {
			v.addf("%s: dhcp ha: %q is not an IPv4 address", p, a)
		}
	}
	if h.This == h.Peer {
		v.addf("%s: dhcp ha: this host and its peer have the same address", p)
	}
}

// ConntrackSyncPort is conntrackd's UDP port between the hosts of a pair.
const ConntrackSyncPort = 3780

// ConntrackSync runs conntrackd in the instance on an HA pair: each host
// sends its connections to the other over Interface, from This to Peer
// (IPv4 addresses on it), and the other puts them in its kernel's table at
// once, so they live on after a failover.
type ConntrackSync struct {
	Interface string `json:"interface"`
	This      string `json:"this"`
	Peer      string `json:"peer"`
}

func (v *validator) conntrackSync(p string, in *Instance) {
	c := in.ConntrackSync
	if c == nil {
		return
	}
	if !ValidIfname(c.Interface) {
		v.addf("%s: conntrack sync: invalid interface %q", p, c.Interface)
	}
	for _, a := range []string{c.This, c.Peer} {
		if ip, err := netip.ParseAddr(a); err != nil || !ip.Is4() {
			v.addf("%s: conntrack sync: %q is not an IPv4 address", p, a)
		}
	}
	if c.This == c.Peer {
		v.addf("%s: conntrack sync: this host and its peer have the same address", p)
	}
}
