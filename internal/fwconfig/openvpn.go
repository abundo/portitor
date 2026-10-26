// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// OpenVPN is an OpenVPN server on an interface of kind KindOpenVPN: remote
// users log in with a user name and password, checked by the agent through
// OpenVPN's management interface: a local user's password against its
// hash, a directory user's (and a user the firewall doesn't have yet) at
// the document's Directory. The server's certificate is one of the instance's
// (Certificates); clients are not asked for one.
//
// The interface is a tun device the agent creates and addresses; OpenVPN
// attaches to it. Its addresses (an IPv4 and/or an IPv6 one) are the
// server's in the tunnel, and the rest of their prefixes are the clients'.
// One OpenVPN process listens on one protocol, so the adaptive mode (UDP,
// and TCP for clients that can't use UDP) runs two: Expand gives the
// interface its UDP process and adds a second device for the TCP one
// (OpenVPNTCPDevice), each with half of the prefixes for its clients
// (Pools). A rule naming the interface matches both (AddOpenVPNDevices).
type OpenVPN struct {
	// Mode is OpenVPNAdaptive, OpenVPNUDP or OpenVPNTCP.
	Mode string `json:"mode"`
	// Port is the UDP and TCP port clients connect to, opened by an auto
	// input rule on Listen.
	Port int `json:"port"`
	// Listen is the interface clients come in on; empty: any.
	Listen string `json:"listen,omitempty"`
	// Certificate is the server's, an instance certificate by name.
	Certificate string `json:"certificate"`
	// TLSCrypt is the static key (OpenVPN's format) that authenticates
	// and encrypts the TLS handshake; clients have it too.
	TLSCrypt string `json:"tls_crypt"`
	// Users are the firewall's users. A user it doesn't have may log in
	// through the Directory, and is then copied to the users.
	Users []OpenVPNUser `json:"users,omitempty"`
	// RequireRole limits the logins to a role's members: the users not
	// Denied, and the directory users in a group mapped to the role
	// (RoleGroups, DNs).
	RequireRole bool     `json:"require_role,omitempty"`
	RoleGroups  []string `json:"role_groups,omitempty"`
	// Routes are pushed to the clients: the networks they reach through
	// the tunnel. RedirectGateway sends all their traffic through it.
	Routes          []string `json:"routes,omitempty"`
	RedirectGateway bool     `json:"redirect_gateway,omitempty"`
	// DNS servers and search domain pushed to the clients.
	DNS       []string `json:"dns,omitempty"`
	DNSDomain string   `json:"dns_domain,omitempty"`
	// ClientToClient lets clients reach each other inside OpenVPN (not
	// through the firewall's rules).
	ClientToClient bool `json:"client_to_client,omitempty"`

	// Set by Expand on each device: its protocol, the prefixes its
	// clients get addresses from, and the interface's whole prefixes,
	// pushed as routes when a pool is half of one.
	Proto    string   `json:"proto,omitempty"`
	Pools    []string `json:"pools,omitempty"`
	Prefixes []string `json:"prefixes,omitempty"`
}

// OpenVPNUser is one of the firewall's users: a local one with the bcrypt
// hash of their password, or a directory user (LDAP), whose password the
// Directory checks. Denied is a user outside the required role, who has
// no hash (a directory user may still be let in by RoleGroups).
type OpenVPNUser struct {
	Name   string `json:"name"`
	Hash   string `json:"hash,omitempty"`
	LDAP   bool   `json:"ldap,omitempty"`
	Denied bool   `json:"denied,omitempty"`
}

// OpenVPN modes and protocols.
const (
	OpenVPNAdaptive = "adaptive"
	OpenVPNUDP      = "udp"
	OpenVPNTCP      = "tcp"
)

// OpenVPNModes are the values of OpenVPN.Mode.
var OpenVPNModes = []string{OpenVPNAdaptive, OpenVPNUDP, OpenVPNTCP}

// OpenVPNPort is OpenVPN's registered port, the default.
const OpenVPNPort = 1194

// Directory's sAMAccountName.
const DefaultLDAPUserFilter = "(|(uid={user})(sAMAccountName={user}))"

// OpenVPNDevicePrefix starts the name of an OpenVPN server's TCP device;
// no interface may be called that.
const OpenVPNDevicePrefix = "ovt-"

// OpenVPNTCPDevice is the device of the TCP process of the adaptive OpenVPN
// server on interface name: "ovt-" and the name, or a hash of it when that
// is too long.
func OpenVPNTCPDevice(name string) string {
	if len(OpenVPNDevicePrefix)+len(name) <= 15 {
		return OpenVPNDevicePrefix + name
	}
	sum := sha256.Sum256([]byte(name))
	return OpenVPNDevicePrefix + hex.EncodeToString(sum[:])[:11]
}

// OpenVPNServer is the instance's OpenVPN interface (not its TCP device),
// or nil.
func (in *Instance) OpenVPNServer() *Interface {
	for i := range in.Interfaces {
		if ifc := &in.Interfaces[i]; ifc.Kind == KindOpenVPN && ifc.Parent == "" && ifc.OpenVPN != nil {
			return ifc
		}
	}
	return nil
}

// OpenVPNDevices are the instance's enabled OpenVPN devices of an expanded
// document, one per OpenVPN process: the interface, and its TCP device.
func (in *Instance) OpenVPNDevices() []*Interface {
	var out []*Interface
	for i := range in.Interfaces {
		if ifc := &in.Interfaces[i]; ifc.Kind == KindOpenVPN && ifc.Enabled && ifc.OpenVPN != nil {
			out = append(out, ifc)
		}
	}
	return out
}

// AddOpenVPNDevices adds to a list of interface names the TCP devices of
// the OpenVPN interfaces in it, sorted: an adaptive server's TCP clients
// come in on that device.
func (in *Instance) AddOpenVPNDevices(names []string) []string {
	out := slices.Clone(names)
	added := false
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindOpenVPN && ifc.Parent != "" && slices.Contains(names, ifc.Parent) && !slices.Contains(out, ifc.Name) {
			out = append(out, ifc.Name)
			added = true
		}
	}
	if added {
		slices.Sort(out)
	}
	return out
}

// addOpenVPNDevices sets each OpenVPN interface's protocol and pools and,
// in the adaptive mode, adds its TCP device, for Expand. The TCP device's
// addresses are the first of the halves of the prefixes the interface's
// addresses aren't in.
func (in *Instance) addOpenVPNDevices() {
	n := len(in.Interfaces)
	for i := 0; i < n; i++ {
		ifc := &in.Interfaces[i]
		if ifc.Kind != KindOpenVPN || ifc.OpenVPN == nil || ifc.Parent != "" {
			continue
		}
		o := *ifc.OpenVPN
		o.Pools, o.Prefixes = nil, nil
		var tcpAddrs, tcpPools []string
		for _, a := range ifc.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			o.Prefixes = append(o.Prefixes, p.Masked().String())
			if o.Mode != OpenVPNAdaptive {
				o.Pools = append(o.Pools, p.Masked().String())
				continue
			}
			own, other, ok := halves(p)
			if !ok {
				continue
			}
			o.Pools = append(o.Pools, own.String())
			tcpPools = append(tcpPools, other.String())
			tcpAddrs = append(tcpAddrs, netip.PrefixFrom(other.Addr().Next(), other.Bits()).String())
		}
		switch o.Mode {
		case OpenVPNTCP:
			o.Proto = OpenVPNTCP
		default:
			o.Proto = OpenVPNUDP
		}
		ifc.OpenVPN = &o
		if o.Mode != OpenVPNAdaptive {
			continue
		}
		t := *ifc
		tcp := o
		tcp.Proto, tcp.Pools = OpenVPNTCP, tcpPools
		t.Name, t.Parent, t.Description = OpenVPNTCPDevice(ifc.Name), ifc.Name, "OpenVPN TCP of "+ifc.Name
		t.Addresses, t.OpenVPN = tcpAddrs, &tcp
		t.ShapeEgress, t.ShapeIngress = 0, 0
		in.Interfaces = append(in.Interfaces, t)
	}
}

// halves splits the prefix of an interface address in two: the half the
// address is in, and the other.
func halves(p netip.Prefix) (own, other netip.Prefix, ok bool) {
	if p.Bits() >= p.Addr().BitLen() {
		return own, other, false
	}
	lo := netip.PrefixFrom(p.Masked().Addr(), p.Bits()+1)
	hi := netip.PrefixFrom(lastAddr(p), p.Bits()+1).Masked()
	if lo.Contains(p.Addr()) {
		return lo, hi, true
	}
	return hi, lo, true
}

// lastAddr is the last address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// OpenVPNPool is the range of a pool its clients get addresses from: the
// longer side of the server's address, without the network address (and
// IPv4's broadcast address).
func OpenVPNPool(pool netip.Prefix, server netip.Addr) (first, last netip.Addr, ok bool) {
	pool = pool.Masked()
	lo, hi := pool.Addr().Next(), lastAddr(pool)
	if pool.Addr().Is4() {
		hi = hi.Prev()
	}
	if !lo.IsValid() || !hi.IsValid() || hi.Less(lo) {
		return first, last, false
	}
	if !server.Less(lo) && !hi.Less(server) {
		if server == lo && server == hi {
			return first, last, false
		}
		if addrCount(lo, server.Prev()).Cmp(addrCount(server.Next(), hi)) >= 0 {
			hi = server.Prev()
		} else {
			lo = server.Next()
		}
	}
	return lo, hi, true
}

// OpenVPNPoolSize is the number of addresses from first to last, at most
// max.
func OpenVPNPoolSize(first, last netip.Addr, max int64) int64 {
	n := addrCount(first, last)
	if n.Cmp(big.NewInt(max)) > 0 {
		return max
	}
	return n.Int64()
}

func addrCount(first, last netip.Addr) *big.Int {
	a, b := new(big.Int).SetBytes(first.AsSlice()), new(big.Int).SetBytes(last.AsSlice())
	n := new(big.Int).Sub(b, a)
	return n.Add(n, big.NewInt(1))
}

// OpenVPNMaxPool is the most clients OpenVPN gives addresses to from one
// pool (its IFCONFIG_POOL_MAX).
const OpenVPNMaxPool = 65536

var (
	tlsCryptRe = regexp.MustCompile(`^-----BEGIN OpenVPN Static key V1-----\n(?:[0-9a-f]{32}\n){16}-----END OpenVPN Static key V1-----\n$`)
	// The names OpenVPN passes on unchanged (it replaces other
	// characters with '_').
	openVPNUserRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
	bcryptRe      = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
)

// GenerateOpenVPNKey makes a static key for tls-crypt, in OpenVPN's
// format (openvpn --genkey secret).
func GenerateOpenVPNKey() (string, error) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	b := &strings.Builder{}
	b.WriteString("-----BEGIN OpenVPN Static key V1-----\n")
	for i := 0; i < len(key); i += 16 {
		b.WriteString(hex.EncodeToString(key[i:i+16]) + "\n")
	}
	b.WriteString("-----END OpenVPN Static key V1-----\n")
	return b.String(), nil
}

// ValidOpenVPNUser checks a name to log in with.
func ValidOpenVPNUser(s string) bool { return openVPNUserRe.MatchString(s) }

// openVPN checks an OpenVPN device of an expanded document.
func (v *validator) openVPN(p string, in *Instance, ifc *Interface) {
	o := ifc.OpenVPN
	if o == nil {
		v.addf("%s: openvpn settings missing", p)
		return
	}
	if !slices.Contains(OpenVPNModes, o.Mode) {
		v.addf("%s: mode must be one of %s", p, strings.Join(OpenVPNModes, ", "))
	}
	if o.Proto != OpenVPNUDP && o.Proto != OpenVPNTCP {
		v.addf("%s: invalid protocol %q", p, o.Proto)
	}
	v.openVPNPools(p, ifc)
	if ifc.Parent != "" {
		return // a TCP device: its interface's settings are checked there
	}
	if o.Port < 1 || o.Port > 65535 {
		v.addf("%s: port must be 1-65535", p)
	}
	if o.Listen != "" && in.Interface(o.Listen) == nil {
		v.addf("%s: unknown listen interface %q", p, o.Listen)
	}
	if !slices.ContainsFunc(in.Certificates, func(c Certificate) bool { return c.Name == o.Certificate }) {
		v.addf("%s: unknown certificate %q", p, o.Certificate)
	}
	if !tlsCryptRe.MatchString(o.TLSCrypt) {
		v.addf("%s: invalid tls-crypt key", p)
	}
	if ifc.IPv4Mode == ModeDHCP {
		v.addf("%s: an OpenVPN interface has static addresses", p)
	}
	users := map[string]bool{}
	for _, u := range o.Users {
		if !ValidOpenVPNUser(u.Name) {
			v.addf("%s: invalid user name %q", p, u.Name)
		}
		local := !u.LDAP && !u.Denied
		if (local && !bcryptRe.MatchString(u.Hash)) || (!local && u.Hash != "") {
			v.addf("%s: user %q: invalid password hash", p, u.Name)
		}
		if users[u.Name] {
			v.addf("%s: duplicate user %q", p, u.Name)
		}
		users[u.Name] = true
	}
	for _, g := range o.RoleGroups {
		if g == "" || !checkLDAPText(g) {
			v.addf("%s: invalid role group %q", p, g)
		}
	}
	for _, r := range o.Routes {
		if _, err := netip.ParsePrefix(r); err != nil {
			v.addf("%s: invalid route %q", p, r)
		}
	}
	for _, d := range o.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			v.addf("%s: invalid DNS server %q", p, d)
		}
	}
	if o.DNSDomain != "" && !validDomain(o.DNSDomain) {
		v.addf("%s: invalid DNS domain %q", p, o.DNSDomain)
	}
}

// openVPNPools checks a device's addresses and pools: at most one address
// per IP version, each with a pool OpenVPN can use.
func (v *validator) openVPNPools(p string, ifc *Interface) {
	o := ifc.OpenVPN
	type family struct {
		addr        string
		first, last netip.Addr
	}
	fams := map[bool]*family{}
	for _, a := range ifc.Addresses {
		if IsDelegated(a) {
			v.addf("%s: an OpenVPN interface takes no delegated address", p)
			continue
		}
		addr, err := netip.ParsePrefix(a)
		if err != nil {
			continue // reported with the interface's addresses
		}
		is4 := addr.Addr().Is4()
		if _, ok := fams[is4]; ok {
			v.addf("%s: one address per IP version", p)
			continue
		}
		fams[is4] = nil
		var pool netip.Prefix
		for _, s := range o.Pools {
			if q, err := netip.ParsePrefix(s); err == nil && q.Contains(addr.Addr()) {
				pool = q
			}
		}
		if !pool.IsValid() {
			v.addf("%s: address %s: no pool", p, a)
			continue
		}
		// OpenVPN's IPv4 pool: up to 65534 clients.
		if is4 && (pool.Bits() < 16 || pool.Bits() > 30) {
			v.addf("%s: address %s: the IPv4 prefix must be /16 to /%d", p, a, 30-boolInt(o.Mode == OpenVPNAdaptive))
			continue
		}
		if !is4 && pool.Bits() > 112 {
			v.addf("%s: address %s: the IPv6 prefix must be /%d or shorter", p, a, 112-boolInt(o.Mode == OpenVPNAdaptive))
			continue
		}
		first, last, ok := OpenVPNPool(pool, addr.Addr())
		if !ok {
			v.addf("%s: address %s: no room for clients", p, a)
			continue
		}
		fams[is4] = &family{a, first, last}
	}
	if len(fams) == 0 {
		v.addf("%s: an OpenVPN interface needs an IPv4 or IPv6 address", p)
	}
	// The IPv6 pool runs from its first address for as many clients as
	// the IPv4 pool has, or, without one, for OpenVPNMaxPool.
	if f6 := fams[false]; f6 != nil {
		need := int64(OpenVPNMaxPool)
		if f4 := fams[true]; f4 != nil {
			need = OpenVPNPoolSize(f4.first, f4.last, OpenVPNMaxPool)
		}
		if OpenVPNPoolSize(f6.first, f6.last, OpenVPNMaxPool) < need {
			v.addf("%s: address %s: no room for %d IPv6 clients on one side of it", p, f6.addr, need)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// openVPNInstance checks what spans an instance's OpenVPN devices: one
// server (one UDP and one TCP process) per instance.
func (v *validator) openVPNInstance(p string, in *Instance) {
	servers := 0
	for _, ifc := range in.Interfaces {
		if ifc.Kind == KindOpenVPN && ifc.Parent == "" {
			servers++
		}
	}
	if servers > 1 {
		v.addf("%s: at most one OpenVPN interface per virtual firewall", p)
	}
}

// Protocols are the ones the server listens on.
func (o *OpenVPN) Protocols() []string {
	switch o.Mode {
	case OpenVPNUDP:
		return []string{OpenVPNUDP}
	case OpenVPNTCP:
		return []string{OpenVPNTCP}
	}
	return []string{OpenVPNUDP, OpenVPNTCP}
}

// CheckOpenVPNAddresses checks an OpenVPN interface's addresses for a mode
// as Validate does (one per IP version, room for the clients of each
// process); it returns the problems.
func CheckOpenVPNAddresses(mode string, addrs []string) []string {
	in := Instance{Interfaces: []Interface{{Name: "x", Kind: KindOpenVPN, Addresses: addrs, OpenVPN: &OpenVPN{Mode: mode}}}}
	in.addOpenVPNDevices()
	v := &validator{}
	for i := range in.Interfaces {
		v.openVPNPools(in.Interfaces[i].Name, &in.Interfaces[i])
	}
	out := make([]string, 0, len(v.problems))
	for _, p := range v.problems {
		_, msg, _ := strings.Cut(p, ": ")
		if !slices.Contains(out, msg) {
			out = append(out, msg)
		}
	}
	return out
}
