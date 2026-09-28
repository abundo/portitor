// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// Service is a port name that port lists accept in place of its number.
type Service struct {
	Name        string `json:"name"`
	Port        int    `json:"port"`
	Description string `json:"description"`
}

// Services are well-known names from /etc/services (IANA), built in so that
// web and agent resolve them alike whatever the host's file says. Where
// Debian and Fedora name a port differently both names are here. Ordered by
// port.
var Services = []Service{
	{"ftp-data", 20, "FTP data"},
	{"ftp", 21, "FTP control"},
	{"ssh", 22, "Secure Shell"},
	{"telnet", 23, "Telnet"},
	{"smtp", 25, "Mail transfer (SMTP)"},
	{"whois", 43, "WHOIS"},
	{"nicname", 43, "WHOIS (Debian name)"},
	{"domain", 53, "DNS"},
	{"bootps", 67, "DHCP server"},
	{"bootpc", 68, "DHCP client"},
	{"tftp", 69, "Trivial FTP"},
	{"http", 80, "Web (HTTP)"},
	{"www", 80, "Web (HTTP, Fedora name)"},
	{"kerberos", 88, "Kerberos"},
	{"pop3", 110, "Mail retrieval (POP3)"},
	{"sunrpc", 111, "RPC portmapper"},
	{"auth", 113, "Ident"},
	{"nntp", 119, "Usenet news (NNTP)"},
	{"ntp", 123, "Network time (NTP)"},
	{"epmap", 135, "Microsoft RPC endpoint mapper"},
	{"netbios-ns", 137, "NetBIOS name service"},
	{"netbios-dgm", 138, "NetBIOS datagram service"},
	{"netbios-ssn", 139, "NetBIOS session service"},
	{"imap", 143, "Mail access (IMAP)"},
	{"imap2", 143, "Mail access (IMAP, Debian name)"},
	{"snmp", 161, "SNMP"},
	{"snmp-trap", 162, "SNMP traps"},
	{"snmptrap", 162, "SNMP traps (Fedora name)"},
	{"bgp", 179, "Border Gateway Protocol"},
	{"ldap", 389, "LDAP directory"},
	{"https", 443, "Web (HTTPS)"},
	{"microsoft-ds", 445, "SMB file sharing"},
	{"isakmp", 500, "IPsec key exchange (IKE)"},
	{"syslog", 514, "Syslog"},
	{"printer", 515, "Line printer daemon (LPD)"},
	{"dhcpv6-client", 546, "DHCPv6 client"},
	{"dhcpv6-server", 547, "DHCPv6 server"},
	{"rtsp", 554, "Real-time streaming (RTSP)"},
	{"submission", 587, "Mail submission"},
	{"ipp", 631, "Internet printing (IPP, CUPS)"},
	{"ldaps", 636, "LDAP over TLS"},
	{"domain-s", 853, "DNS over TLS"},
	{"rsync", 873, "rsync daemon"},
	{"ftps", 990, "FTP over TLS"},
	{"imaps", 993, "IMAP over TLS"},
	{"pop3s", 995, "POP3 over TLS"},
	{"socks", 1080, "SOCKS proxy"},
	{"openvpn", 1194, "OpenVPN"},
	{"ms-sql-s", 1433, "Microsoft SQL Server"},
	{"l2tp", 1701, "L2TP"},
	{"pptp", 1723, "PPTP VPN"},
	{"radius", 1812, "RADIUS authentication"},
	{"radius-acct", 1813, "RADIUS accounting"},
	{"mqtt", 1883, "MQTT"},
	{"nfs", 2049, "NFS"},
	{"iscsi-target", 3260, "iSCSI target"},
	{"mysql", 3306, "MySQL / MariaDB"},
	{"ms-wbt-server", 3389, "Remote Desktop (RDP)"},
	{"nut", 3493, "Network UPS Tools"},
	{"svn", 3690, "Subversion"},
	{"ipsec-nat-t", 4500, "IPsec NAT traversal"},
	{"munin", 4949, "Munin node"},
	{"sip", 5060, "SIP"},
	{"sip-tls", 5061, "SIP over TLS"},
	{"xmpp-client", 5222, "XMPP client"},
	{"xmpp-server", 5269, "XMPP server"},
	{"mdns", 5353, "Multicast DNS"},
	{"postgresql", 5432, "PostgreSQL"},
	{"postgres", 5432, "PostgreSQL (Fedora name)"},
	{"amqp", 5672, "AMQP message queue"},
	{"x11", 6000, "X Window System"},
	{"http-alt", 8080, "Alternative HTTP"},
	{"webcache", 8080, "Web cache (Fedora name for 8080)"},
	{"puppet", 8140, "Puppet"},
	{"secure-mqtt", 8883, "MQTT over TLS"},
	{"git", 9418, "Git daemon"},
	{"zabbix-agent", 10050, "Zabbix agent"},
	{"zabbix-trapper", 10051, "Zabbix server (trapper)"},
}

var servicePorts = func() map[string]int {
	m := make(map[string]int, len(Services))
	for _, s := range Services {
		m[s.Name] = s.Port
	}
	return m
}()

// ServicePort returns the port of a service name in Services.
func ServicePort(name string) (int, bool) {
	p, ok := servicePorts[name]
	return p, ok
}
