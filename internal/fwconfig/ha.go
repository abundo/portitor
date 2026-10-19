// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"net/netip"
	"net/url"
	"regexp"
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
	// Secret is shared by the pair for the heartbeat (/v1/ha/heartbeat),
	// the only route it opens.
	Secret string `json:"secret"`
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
