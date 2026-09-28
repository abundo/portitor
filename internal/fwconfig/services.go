// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

// Service is a port name that port lists accept in place of its number.
type Service struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}

// Services are well-known names from /etc/services (IANA), built in so that
// web and agent resolve them alike whatever the host's file says. Where
// Debian and Fedora name a port differently both names are here. Ordered by
// port.
var Services = []Service{
	{"ftp-data", 20}, {"ftp", 21}, {"ssh", 22}, {"telnet", 23}, {"smtp", 25},
	{"whois", 43}, {"nicname", 43}, {"domain", 53}, {"bootps", 67}, {"bootpc", 68},
	{"tftp", 69}, {"http", 80}, {"www", 80}, {"kerberos", 88}, {"pop3", 110},
	{"sunrpc", 111}, {"auth", 113}, {"nntp", 119}, {"ntp", 123}, {"epmap", 135},
	{"netbios-ns", 137}, {"netbios-dgm", 138}, {"netbios-ssn", 139},
	{"imap", 143}, {"imap2", 143}, {"snmp", 161}, {"snmp-trap", 162}, {"snmptrap", 162},
	{"bgp", 179}, {"ldap", 389}, {"https", 443}, {"microsoft-ds", 445},
	{"isakmp", 500}, {"syslog", 514}, {"printer", 515}, {"dhcpv6-client", 546},
	{"dhcpv6-server", 547}, {"rtsp", 554}, {"submission", 587}, {"ipp", 631},
	{"ldaps", 636}, {"domain-s", 853}, {"rsync", 873}, {"ftps", 990},
	{"imaps", 993}, {"pop3s", 995}, {"socks", 1080}, {"openvpn", 1194},
	{"ms-sql-s", 1433}, {"l2tp", 1701}, {"pptp", 1723}, {"radius", 1812},
	{"radius-acct", 1813}, {"mqtt", 1883}, {"nfs", 2049}, {"iscsi-target", 3260},
	{"mysql", 3306}, {"ms-wbt-server", 3389}, {"nut", 3493}, {"svn", 3690},
	{"ipsec-nat-t", 4500}, {"munin", 4949}, {"sip", 5060}, {"sip-tls", 5061},
	{"xmpp-client", 5222}, {"xmpp-server", 5269}, {"mdns", 5353},
	{"postgresql", 5432}, {"postgres", 5432}, {"amqp", 5672}, {"x11", 6000},
	{"http-alt", 8080}, {"webcache", 8080}, {"puppet", 8140}, {"secure-mqtt", 8883},
	{"git", 9418}, {"zabbix-agent", 10050}, {"zabbix-trapper", 10051},
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
