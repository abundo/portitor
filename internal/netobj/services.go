// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netobj

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Service names are lower case and start with a letter.
var serviceNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

// ValidServiceName reports whether s can name a custom service: it must not
// be a predefined name either.
func ValidServiceName(s string) bool {
	_, predefined := predefinedByName[s]
	return serviceNameRe.MatchString(s) && !predefined && s != "any"
}

func ports(desc string, list ...models.ServicePort) models.Service {
	return models.Service{Type: models.ServiceTypePorts, Ports: list, Description: desc}
}

func tcp(lo, hi int) models.ServicePort {
	return models.ServicePort{Protocol: "tcp", DstLo: lo, DstHi: hi}
}
func udp(lo, hi int) models.ServicePort {
	return models.ServicePort{Protocol: "udp", DstLo: lo, DstHi: hi}
}
func sctp(lo, hi int) models.ServicePort {
	return models.ServicePort{Protocol: "sctp", DstLo: lo, DstHi: hi}
}

func both(lo, hi int) []models.ServicePort {
	return []models.ServicePort{tcp(lo, hi), udp(lo, hi)}
}

func icmp(typ, desc string) models.Service {
	return models.Service{Type: models.ServiceTypeICMP, IcmpType: typ, Description: desc}
}

func icmp6(typ, desc string) models.Service {
	return models.Service{Type: models.ServiceTypeICMP6, IcmpType: typ, Description: desc}
}

func ipProto(n int, desc string) models.Service {
	return models.Service{Type: models.ServiceTypeIP, IpProtocol: n, Description: desc}
}

func named(name string, s models.Service) models.Service {
	s.Name = name
	return s
}

// Predefined are the services every installation has, by name. They are
// not stored in the database; rules name them like custom services.
var Predefined = []models.Service{
	named("all", ipProto(0, "Any protocol")),
	named("all-tcp", ports("Any TCP port", tcp(1, 65535))),
	named("all-udp", ports("Any UDP port", udp(1, 65535))),
	named("all-sctp", ports("Any SCTP port", sctp(1, 65535))),
	named("all-icmp", icmp("", "Any ICMP")),
	named("all-icmp6", icmp6("", "Any ICMPv6")),
	named("ping", icmp("echo-request", "ICMP echo request")),
	named("ping6", icmp6("echo-request", "ICMPv6 echo request")),
	named("ah", ipProto(51, "IPsec authentication header")),
	named("bgp", ports("BGP", tcp(179, 0))),
	named("dhcp", ports("DHCP", udp(67, 68))),
	named("dhcp6", ports("DHCPv6", udp(546, 547))),
	named("dns", ports("DNS", both(53, 0)...)),
	named("dns-over-tls", ports("DNS over TLS", tcp(853, 0))),
	named("esp", ipProto(50, "IPsec encapsulating security payload")),
	named("ftp", ports("FTP control", tcp(21, 0))),
	named("gre", ipProto(47, "Generic routing encapsulation")),
	named("http", ports("Web (HTTP)", tcp(80, 0))),
	named("https", ports("Web (HTTPS, HTTP/3)", tcp(443, 0), udp(443, 0))),
	named("ike", ports("IPsec key exchange (IKE, NAT traversal)", udp(500, 0), udp(4500, 0))),
	named("imap", ports("Mail access (IMAP)", tcp(143, 0))),
	named("imaps", ports("Mail access (IMAP over TLS)", tcp(993, 0))),
	named("kerberos", ports("Kerberos", both(88, 0)...)),
	named("ldap", ports("LDAP", tcp(389, 0))),
	named("ldaps", ports("LDAP over TLS", tcp(636, 0))),
	named("mqtt", ports("MQTT", tcp(1883, 0), tcp(8883, 0))),
	named("mysql", ports("MySQL, MariaDB", tcp(3306, 0))),
	named("nfs", ports("NFS", both(2049, 0)...)),
	named("ntp", ports("Time (NTP)", udp(123, 0))),
	named("ospf", ipProto(89, "OSPF")),
	named("pop3", ports("Mail access (POP3)", tcp(110, 0))),
	named("pop3s", ports("Mail access (POP3 over TLS)", tcp(995, 0))),
	named("postgresql", ports("PostgreSQL", tcp(5432, 0))),
	named("rdp", ports("Remote desktop (RDP)", tcp(3389, 0), udp(3389, 0))),
	named("sip", ports("SIP", both(5060, 0)...)),
	named("smb", ports("Windows file sharing (SMB)", tcp(445, 0))),
	named("smtp", ports("Mail transfer (SMTP)", tcp(25, 0))),
	named("smtps", ports("Mail submission over TLS", tcp(465, 0))),
	named("snmp", ports("SNMP", udp(161, 162))),
	named("ssh", ports("Secure Shell", tcp(22, 0))),
	named("submission", ports("Mail submission", tcp(587, 0))),
	named("syslog", ports("Syslog", udp(514, 0))),
	named("telnet", ports("Telnet", tcp(23, 0))),
	named("tftp", ports("Trivial FTP", udp(69, 0))),
	named("traceroute", ports("Traceroute (UDP probes)", udp(33434, 33534))),
	named("vnc", ports("VNC", tcp(5900, 0))),
	named("vrrp", ipProto(112, "VRRP")),
	named("wireguard", ports("WireGuard (default port)", udp(51820, 0))),
}

var predefinedByName = func() map[string]models.Service {
	m := make(map[string]models.Service, len(Predefined))
	for _, s := range Predefined {
		m[s.Name] = s
	}
	return m
}()

// CheckService checks a service's fields for its type; fields of other
// types must be empty.
func CheckService(s models.Service) error {
	switch s.Type {
	case models.ServiceTypePorts:
		if len(s.Ports) == 0 {
			return errors.New("ports: add at least one protocol and port range")
		}
		for i, p := range s.Ports {
			where := fmt.Sprintf("ports: entry %d", i+1)
			if !slices.Contains([]string{"tcp", "udp", "sctp"}, p.Protocol) {
				return fmt.Errorf("%s: protocol must be tcp, udp or sctp", where)
			}
			if err := checkRange(p.DstLo, p.DstHi); err != nil {
				return fmt.Errorf("%s: destination port %v", where, err)
			}
			if err := checkRange(p.SrcLo, p.SrcHi); err != nil {
				return fmt.Errorf("%s: source port %v", where, err)
			}
		}
	case models.ServiceTypeICMP, models.ServiceTypeICMP6:
		proto := icmpProto(s.Type)
		if s.IcmpType != "" && !fwconfig.ValidICMPType(proto, s.IcmpType) {
			return fmt.Errorf("type: unknown %s type %q", proto, s.IcmpType)
		}
		if s.IcmpCode != nil {
			if s.IcmpType == "" {
				return errors.New("code: needs a type")
			}
			if *s.IcmpCode < 0 || *s.IcmpCode > 255 {
				return errors.New("code: 0 to 255")
			}
		}
	case models.ServiceTypeIP:
		if s.IpProtocol < 0 || s.IpProtocol > 255 {
			return errors.New("protocol number: 0 (any) to 255")
		}
	default:
		return fmt.Errorf("type: must be %s, %s, %s or %s", models.ServiceTypePorts, models.ServiceTypeICMP, models.ServiceTypeICMP6, models.ServiceTypeIP)
	}
	return nil
}

// checkRange checks a port range; lo 0 is no range, hi 0 is lo.
func checkRange(lo, hi int) error {
	switch {
	case lo == 0 && hi == 0:
		return nil
	case lo < 1 || lo > 65535 || hi < 0 || hi > 65535:
		return errors.New("must be 1 to 65535")
	case hi != 0 && hi < lo:
		return errors.New("high is below low")
	}
	return nil
}

func icmpProto(typ string) string {
	if typ == models.ServiceTypeICMP6 {
		return fwconfig.ProtoICMPv6
	}
	return fwconfig.ProtoICMP
}

func portRange(lo, hi int) string {
	switch {
	case lo == 0:
		return ""
	case hi == 0 || hi == lo:
		return fmt.Sprint(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

// Matches returns the protocol matches of a checked service.
func Matches(s models.Service) []fwconfig.ServiceMatch {
	switch s.Type {
	case models.ServiceTypePorts:
		out := make([]fwconfig.ServiceMatch, 0, len(s.Ports))
		for _, p := range s.Ports {
			out = append(out, fwconfig.ServiceMatch{
				Protocol: p.Protocol,
				DstPorts: portRange(p.DstLo, p.DstHi),
				SrcPorts: portRange(p.SrcLo, p.SrcHi),
			})
		}
		return out
	case models.ServiceTypeICMP, models.ServiceTypeICMP6:
		m := fwconfig.ServiceMatch{Protocol: icmpProto(s.Type), ICMPType: s.IcmpType}
		if s.IcmpCode != nil {
			code := *s.IcmpCode
			m.ICMPCode = &code
		}
		return []fwconfig.ServiceMatch{m}
	case models.ServiceTypeIP:
		return []fwconfig.ServiceMatch{{Protocol: fwconfig.ProtoIP, IPProtocol: s.IpProtocol}}
	}
	return nil
}

// Services resolves the service names rules hold: custom services
// (models.Service) and the predefined ones. portitor-web expands them when
// it builds the document, so the agent only ever sees protocol matches.
type Services map[string]models.Service

func NewServices(custom []models.Service) Services {
	s := Services{}
	for _, svc := range Predefined {
		s[svc.Name] = svc
	}
	for _, svc := range custom {
		s[svc.Name] = svc
	}
	return s
}

// Expand returns the protocol matches of the named services, without
// duplicates. Destination ports of the same protocol and source ports are
// merged into one list ("80,443"), so they render as one nft rule. An
// unknown name is an error, never a skipped entry: an empty result would
// match any protocol.
func (s Services) Expand(names []string) ([]fwconfig.ServiceMatch, error) {
	var out []fwconfig.ServiceMatch
	for _, n := range names {
		svc, ok := s[n]
		if !ok {
			return nil, fmt.Errorf("unknown service %q", n)
		}
	next:
		for _, m := range Matches(svc) {
			for i, o := range out {
				if sameMatch(o, m) {
					continue next
				}
				if m.DstPorts != "" && o.DstPorts != "" && o.Protocol == m.Protocol && o.SrcPorts == m.SrcPorts {
					if !slices.Contains(strings.Split(o.DstPorts, ","), m.DstPorts) {
						out[i].DstPorts += "," + m.DstPorts
					}
					continue next
				}
			}
			out = append(out, m)
		}
	}
	return out, nil
}

func sameMatch(a, b fwconfig.ServiceMatch) bool {
	if (a.ICMPCode == nil) != (b.ICMPCode == nil) || (a.ICMPCode != nil && *a.ICMPCode != *b.ICMPCode) {
		return false
	}
	a.ICMPCode, b.ICMPCode = nil, nil
	return a == b
}
