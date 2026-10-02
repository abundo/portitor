// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package models is the GORM mapping of portitor-web's database. The schema
// itself is owned by the goose migrations in internal/dbmigrate/sql; keep
// both in step.
package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

type Base struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (b *Base) GetID() uint   { return b.ID }
func (b *Base) SetID(id uint) { b.ID = id }

// StringList is stored as a JSON array in a TEXT column.
type StringList []string

func (s StringList) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(s))
	return string(b), err
}

func (s *StringList) Scan(src any) error {
	var data []byte
	switch v := src.(type) {
	case nil:
		*s = StringList{}
		return nil
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("StringList: unsupported type")
	}
	var out []string
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*s = out
	return nil
}

func (s StringList) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(s))
}

func (StringList) GormDataType() string { return "text" }

// StringMap is stored as a JSON object in a TEXT column.
type StringMap map[string]string

func (m StringMap) Value() (driver.Value, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(map[string]string(m))
	return string(b), err
}

func (m *StringMap) Scan(src any) error {
	var data []byte
	switch v := src.(type) {
	case nil:
		*m = StringMap{}
		return nil
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("StringMap: unsupported type")
	}
	out := map[string]string{}
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*m = out
	return nil
}

func (StringMap) GormDataType() string { return "text" }

// ServicePort is one protocol entry of a service of type
// ServiceTypePorts: a destination port range and optionally a source port
// range. Lo 0 leaves a range out (any port); Hi 0 is Lo.
type ServicePort struct {
	Protocol string `json:"protocol"` // tcp, udp or sctp
	DstLo    int    `json:"dst_lo"`
	DstHi    int    `json:"dst_hi"`
	SrcLo    int    `json:"src_lo"`
	SrcHi    int    `json:"src_hi"`
}

// ServicePortList is stored as a JSON array in a TEXT column.
type ServicePortList []ServicePort

func (s ServicePortList) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]ServicePort(s))
	return string(b), err
}

func (s *ServicePortList) Scan(src any) error {
	var data []byte
	switch v := src.(type) {
	case nil:
		*s = ServicePortList{}
		return nil
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("ServicePortList: unsupported type")
	}
	var out []ServicePort
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*s = out
	return nil
}

func (s ServicePortList) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]ServicePort(s))
}

func (ServicePortList) GormDataType() string { return "text" }

// DnsNameserver is one apex NS of a DnsTemplate, with an optional IPv4 or
// IPv6 Address; a nameserver with both is listed twice. When Name is in a
// zone of the instance, the builder adds the address to that zone as an A
// or AAAA record.
type DnsNameserver struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// UnmarshalJSON also takes a bare name, as nameservers were before they
// had addresses.
func (n *DnsNameserver) UnmarshalJSON(b []byte) error {
	var name string
	if json.Unmarshal(b, &name) == nil {
		*n = DnsNameserver{Name: name}
		return nil
	}
	type plain DnsNameserver
	return json.Unmarshal(b, (*plain)(n))
}

// DnsNameserverList is stored as a JSON array in a TEXT column.
type DnsNameserverList []DnsNameserver

func (l DnsNameserverList) Value() (driver.Value, error) {
	if l == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]DnsNameserver(l))
	return string(b), err
}

func (l *DnsNameserverList) Scan(src any) error {
	var data []byte
	switch v := src.(type) {
	case nil:
		*l = DnsNameserverList{}
		return nil
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return errors.New("DnsNameserverList: unsupported type")
	}
	var out []DnsNameserver
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	*l = out
	return nil
}

func (l DnsNameserverList) MarshalJSON() ([]byte, error) {
	if l == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]DnsNameserver(l))
}

// Names returns the nameservers' names, each once.
func (l DnsNameserverList) Names() []string {
	out := []string{}
	for _, n := range l {
		if !slices.Contains(out, n.Name) {
			out = append(out, n.Name)
		}
	}
	return out
}

func (DnsNameserverList) GormDataType() string { return "text" }

type User struct {
	Base
	Username     string `gorm:"uniqueIndex" json:"username"`
	FullName     string `json:"full_name"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	// Role is RoleAdmin or RoleViewer.
	Role string `json:"role"`
	// TokenVersion invalidates issued sessions when bumped (password
	// change, role change, logout everywhere).
	TokenVersion int `json:"-"`
}

const (
	// RoleAdmin may do everything.
	RoleAdmin = "admin"
	// RoleViewer reads the configuration and status but changes nothing
	// except their own profile and password.
	RoleViewer = "viewer"
	// RoleNone has no access of its own: only what the user's roles grant
	// on instances.
	RoleNone = "none"
)

// Role groups users. A role with an InstanceID belongs to that instance:
// it is created, renamed and removed with the instance, never by hand.
type Role struct {
	Base
	Name        string `gorm:"uniqueIndex" json:"name"`
	Description string `json:"description"`
	InstanceID  *uint  `json:"instance_id"`
	// Members and InstanceIDs (the instances a role made by hand grants)
	// are filled by the roles API, not stored with the row.
	Members     []RoleMember `gorm:"-" json:"members"`
	InstanceIDs []uint       `gorm:"-" json:"instance_ids"`
}

// RoleInstance grants a role made by hand an instance.
type RoleInstance struct {
	Base
	RoleID     uint `json:"role_id"`
	InstanceID uint `json:"instance_id"`
}

// RoleMember puts a user in a role, as RoleAdmin or RoleViewer.
type RoleMember struct {
	Base
	RoleID uint   `json:"role_id"`
	UserID uint   `json:"user_id"`
	Level  string `json:"level"`
}

// Settings is a single row (ID 1).
type Settings struct {
	ID uint `gorm:"primaryKey" json:"id"`
	// AgentURL is the portitor-agent API, e.g. https://192.168.1.1:8443.
	AgentURL string `json:"agent_url"`
	// AgentToken authenticates to the agent. Never sent to the browser.
	AgentToken string `json:"-"`
	// AgentFingerprint pins the agent's self-signed certificate
	// (SHA-256 of the DER, hex). Empty means verify against system CAs.
	AgentFingerprint string `json:"agent_fingerprint"`
	// ConfirmTimeout is the default commit-confirm window in seconds;
	// 0 applies without confirmation.
	ConfirmTimeout int `json:"confirm_timeout"`
	// WgEndpointHost is the public name/address road-warrior clients
	// connect to, for generated client configs.
	WgEndpointHost string `json:"wg_endpoint_host"`
	// CaptureRateKbps caps a packet capture's stream from the agent
	// (kbit/s); 0 is unlimited.
	CaptureRateKbps int `gorm:"default:1000" json:"capture_rate_kbps"`
	// WebCertificateID is the certificate (Certificates page) portitor-web
	// serves HTTPS with, when it serves HTTPS itself (tls_cert); nil
	// serves tls_cert.
	WebCertificateID *uint `json:"web_certificate_id"`
	// Generation is the last deployed document generation.
	Generation int64     `json:"generation"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Instance is a virtual router: its own network namespace, routing
// table, firewall, DNS and DHCP server.
type Instance struct {
	Base
	Name        string `gorm:"uniqueIndex" json:"name"`
	Description string `json:"description"`
	IsDefault   bool   `json:"is_default"`

	DnsEnabled          bool       `json:"dns_enabled"`
	DnsUpstream         string     `json:"dns_upstream"` // fwconfig.Upstream*
	DnsForwarders       StringList `json:"dns_forwarders"`
	DnsForwardMode      string     `json:"dns_forward_mode"` // fwconfig.ForwardFirst or ForwardOnly
	DnsAllowRecursion   StringList `json:"dns_allow_recursion"`
	DnsDnssecValidation string     `json:"dns_dnssec_validation"` // fwconfig.DNSSECValidationAuto or No

	DhcpEnabled    bool   `json:"dhcp_enabled"`
	DhcpDomainName string `json:"dhcp_domain_name"`
	DhcpLeaseTime  int    `json:"dhcp_lease_time"`

	// LogDrops lists the filter chains whose policy drops are logged,
	// LogInvalid those whose invalid packet drops are, and LogAuto the auto
	// input rules (by service) whose matches are.
	LogDrops   StringList `json:"log_drops"`
	LogInvalid StringList `json:"log_invalid"`
	LogAuto    StringList `json:"log_auto"`
}

// InterfaceZone is a named group of zero or more interfaces of an
// instance, by name (link ends included). Rules and NAT rules list
// interface and interface zone names.
type InterfaceZone struct {
	Base
	InstanceID  uint       `json:"instance_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Interfaces  StringList `json:"interfaces"`
}

type Interface struct {
	Base
	InstanceID uint   `json:"instance_id"`
	Name       string `json:"name"`
	// Label is a short name the GUI shows before the interface name.
	Label       string     `json:"label"`
	Kind        string     `json:"kind"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
	Parent      string     `json:"parent"`
	VlanID      int        `json:"vlan_id"`
	Members     StringList `json:"members"`
	Mtu         int        `json:"mtu"`
	Ipv4Mode    string     `json:"ipv4_mode"`
	// Addresses are the interface's static addresses in CIDR form with a
	// host part (192.168.1.1/24, fd00:1::1/64), IPv4 and IPv6 mixed.
	Addresses    StringList `json:"addresses"`
	Ipv6AcceptRA bool       `gorm:"column:ipv6_accept_ra" json:"ipv6_accept_ra"`
	// Dhcpv6 runs a DHCPv6 client; Dhcpv6Pd also asks for a delegated
	// prefix, of Dhcpv6PdLength bits (0: the server chooses).
	Dhcpv6         bool `gorm:"column:dhcpv6" json:"dhcpv6"`
	Dhcpv6Pd       bool `gorm:"column:dhcpv6_pd" json:"dhcpv6_pd"`
	Dhcpv6PdLength int  `gorm:"column:dhcpv6_pd_length" json:"dhcpv6_pd_length"`
	// DhcpNoDefaultRoute ignores the router of the DHCP lease.
	DhcpNoDefaultRoute bool `json:"dhcp_no_default_route"`
	// DnsListen makes the instance's DNS server answer on this interface.
	DnsListen bool `json:"dns_listen"`
	// DnsFromDhcp: with DNS upstream dhcp, the DNS servers of this
	// interface's DHCP lease are the forwarders. At most one per instance.
	DnsFromDhcp bool `json:"dns_from_dhcp"`
	// Lldp sends LLDP on the interface and lists its LLDP neighbours
	// (physical, VLAN and bridge interfaces).
	Lldp bool `gorm:"column:lldp" json:"lldp"`

	WgPrivateKey string `json:"-"`
	WgPublicKey  string `json:"wg_public_key"`
	WgListenPort int    `json:"wg_listen_port"`
	// WgEndpoint (host:port) and WgKeepalive go into generated client
	// configs. An empty endpoint falls back to Settings.WgEndpointHost
	// and the listen port.
	WgEndpoint  string `json:"wg_endpoint"`
	WgKeepalive int    `json:"wg_keepalive"`
}

type WgPeer struct {
	Base
	InterfaceID  uint       `json:"interface_id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	PublicKey    string     `json:"public_key"`
	PresharedKey string     `json:"-"`
	Endpoint     string     `json:"endpoint"`
	AllowedIPs   StringList `gorm:"column:allowed_ips" json:"allowed_ips"`
	// Networks behind a site peer: routed through the interface.
	Networks  StringList `json:"networks"`
	Keepalive int        `json:"keepalive"`
	// ClientPrivateKey is kept only when the key pair was generated
	// here, so a complete client config can be exported.
	ClientPrivateKey string `json:"-"`
	HasPresharedKey  bool   `gorm:"-" json:"has_preshared_key"`
	HasClientKey     bool   `gorm:"-" json:"has_client_key"`
}

// Link is a point-to-point connection between two instances (veth pair).
type Link struct {
	Base
	Name        string     `gorm:"uniqueIndex" json:"name"`
	Description string     `json:"description"`
	InstanceAID uint       `gorm:"column:instance_a_id" json:"instance_a_id"`
	InterfaceA  string     `gorm:"column:interface_a" json:"interface_a"`
	AddressesA  StringList `gorm:"column:addresses_a" json:"addresses_a"`
	InstanceBID uint       `gorm:"column:instance_b_id" json:"instance_b_id"`
	InterfaceB  string     `gorm:"column:interface_b" json:"interface_b"`
	AddressesB  StringList `gorm:"column:addresses_b" json:"addresses_b"`
}

type Route struct {
	Base
	InstanceID  uint   `json:"instance_id"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	InterfaceID *uint  `json:"interface_id"`
	Metric      int    `json:"metric"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

type Rule struct {
	Base
	InstanceID uint   `json:"instance_id"`
	Position   int    `json:"position"`
	Chain      string `json:"chain"`
	// Kind is empty for a rule, RuleKindComment for a comment row or
	// RuleKindGroup for a group section heading; both keep their text in
	// Description and only annotate the list. A group holds the rows below
	// it up to the next group (the GUI folds them).
	Kind string `json:"kind"`
	// InInterfaces and OutInterfaces hold interface and interface zone
	// names of the instance; empty matches any.
	InInterfaces  StringList `json:"in_interfaces"`
	OutInterfaces StringList `json:"out_interfaces"`
	Family        string     `json:"family"`
	SrcAddrs      StringList `json:"src_addrs"`
	DstAddrs      StringList `json:"dst_addrs"`
	// Services holds names of services (custom or predefined); empty
	// matches any protocol.
	Services    StringList `json:"services"`
	Action      string     `json:"action"`
	Log         bool       `json:"log"`
	Enabled     bool       `json:"enabled"`
	Description string     `json:"description"`
}

// Rule kinds besides a rule ("").
const (
	RuleKindComment = "comment" // a comment row between rules
	RuleKindGroup   = "group"   // a group section heading
)

// IsNote reports whether r is a comment row or group heading rather than a
// rule.
func (r Rule) IsNote() bool {
	return r.Kind == RuleKindComment || r.Kind == RuleKindGroup
}

type NatRule struct {
	Base
	InstanceID    uint       `json:"instance_id"`
	Position      int        `json:"position"`
	Kind          string     `json:"kind"`
	InInterfaces  StringList `json:"in_interfaces"`
	OutInterfaces StringList `json:"out_interfaces"`
	Protocol      string     `json:"protocol"`
	SrcAddrs      StringList `json:"src_addrs"`
	DstAddrs      StringList `json:"dst_addrs"`
	DstPorts      string     `json:"dst_ports"`
	ToAddr        string     `json:"to_addr"`
	ToPort        int        `json:"to_port"`
	Enabled       bool       `json:"enabled"`
	Description   string     `json:"description"`
}

// IpamPrefix is a node in the prefix tree. Parent/child relations are not
// stored; they follow from CIDR containment within an instance.
type IpamPrefix struct {
	Base
	InstanceID     uint       `json:"instance_id"`
	Prefix         string     `json:"prefix"`
	Description    string     `json:"description"`
	DhcpEnabled    bool       `json:"dhcp_enabled"`
	DhcpRangeStart string     `json:"dhcp_range_start"`
	DhcpRangeEnd   string     `json:"dhcp_range_end"`
	DhcpGateway    string     `json:"dhcp_gateway"`
	DhcpDnsServers StringList `json:"dhcp_dns_servers"`
	// RaEnabled sends IPv6 router advertisements for the prefix on the
	// interface that has an address in it; RaSlaac lets clients pick
	// their own address (/64 only).
	RaEnabled bool `json:"ra_enabled"`
	RaSlaac   bool `json:"ra_slaac"`
}

// AddressObject is a named host or prefix. Its name can stand in for
// addresses wherever an address list is entered; the builder expands it.
// Addresses may mix IPv4 and IPv6 (a host with both, say).
type AddressObject struct {
	Base
	Name        string     `gorm:"uniqueIndex" json:"name"`
	Addresses   StringList `json:"addresses"`
	Description string     `json:"description"`
	FolderID    *uint      `json:"folder_id"`
}

// ObjectFolder is a folder in the GUI for hosts (AddressObject.FolderID)
// or IP lists (IpList.FolderID), by Kind. Folders nest (ParentID, nil at
// the top) and mean nothing to the firewall.
type ObjectFolder struct {
	Base
	Kind     string `json:"kind"` // ObjectFolder*
	ParentID *uint  `json:"parent_id"`
	Name     string `json:"name"`
}

// Kinds of ObjectFolder.
const (
	ObjectFolderHosts   = "hosts"
	ObjectFolderIpLists = "ip_lists"
)

// Service is a named protocol match that rules refer to by name, next to
// the predefined ones (netobj.Predefined); the builder expands the names.
// Type says which fields apply: Ports (tcp, udp, sctp), IcmpType and
// IcmpCode (icmp, icmp6), or IpProtocol (ip).
type Service struct {
	Base
	Name        string          `gorm:"uniqueIndex" json:"name"`
	Description string          `json:"description"`
	Type        string          `json:"type"`
	Ports       ServicePortList `json:"ports"`
	// IcmpType is an ICMP or ICMPv6 type name and IcmpCode its code;
	// empty or nil matches any.
	IcmpType string `json:"icmp_type"`
	IcmpCode *int   `json:"icmp_code"`
	// IpProtocol is an IP protocol number; 0 matches any.
	IpProtocol int `json:"ip_protocol"`
}

// Service types.
const (
	ServiceTypePorts = "tcp/udp/sctp"
	ServiceTypeICMP  = "icmp"
	ServiceTypeICMP6 = "icmp6"
	ServiceTypeIP    = "ip"
)

// IpamAddress is a single address. With DnsName it gets an A/AAAA record;
// with Mac also a DHCP reservation. The firewall's own addresses are
// configured on the interface (Interface.Addresses).
type IpamAddress struct {
	Base
	InstanceID  uint   `json:"instance_id"`
	Address     string `json:"address"`
	DnsName     string `json:"dns_name"`
	Mac         string `json:"mac"`
	Description string `json:"description"`
}

type DnsZone struct {
	Base
	InstanceID uint   `json:"instance_id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	// DnsTemplateID nil: built-in SOA and NS (localhost).
	DnsTemplateID *uint  `json:"dns_template_id"`
	Description   string `json:"description"`
}

// DnsSoaTemplate is shared by all instances. Minimum is the SOA minimum
// (negative-caching TTL); the serial is dnsmgr2's.
type DnsSoaTemplate struct {
	Base
	Name    string `json:"name"`
	Mname   string `json:"mname"`
	Rname   string `json:"rname"`
	Refresh int64  `json:"refresh"`
	Retry   int64  `json:"retry"`
	Expire  int64  `json:"expire"`
	Minimum int64  `json:"minimum"`
}

type DnsDnssecPolicy struct {
	Base
	Name                     string `json:"name"`
	KskLifetime              string `json:"ksk_lifetime"`
	KskAlgorithm             string `json:"ksk_algorithm"`
	ZskLifetime              string `json:"zsk_lifetime"`
	ZskAlgorithm             string `json:"zsk_algorithm"`
	PurgeKeys                string `json:"purge_keys"`
	SignaturesValidity       string `json:"signatures_validity"`
	SignaturesValidityDnskey string `gorm:"column:signatures_validity_dnskey" json:"signatures_validity_dnskey"`
	SignaturesRefresh        string `json:"signatures_refresh"`
}

// DnsTemplate is a zone template: SOA, default TTL, apex NS and an
// optional DNSSEC policy. Shared by all instances.
type DnsTemplate struct {
	Base
	Name           string            `json:"name"`
	SoaTemplateID  uint              `json:"soa_template_id"`
	DefaultTtl     int64             `json:"default_ttl"`
	DnssecPolicyID *uint             `json:"dnssec_policy_id"`
	Nameservers    DnsNameserverList `json:"nameservers"`
	Description    string            `json:"description"`
}

// DnsRecord is one row of a zone's record grid, in Rank order. Type
// COMMENT (text in Value) and $DOMAIN (a subdomain in Name, applied to the
// rows below it) are editor-only; see builder.RecordName.
type DnsRecord struct {
	Base
	ZoneID      uint   `json:"zone_id"`
	Rank        int    `json:"rank"`
	Name        string `json:"name"`
	Ttl         int64  `json:"ttl"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Mac         string `json:"mac"`
	Description string `json:"description"`
}

// Editor-only record types.
const (
	DnsRecordComment = "COMMENT"
	DnsRecordDomain  = "$DOMAIN"
)

// DyndnsClient (a DNS update client) keeps DyndnsRecords in step with the
// addresses of an interface of its instance: on the nameserver Server by
// RFC 2136 UPDATE, or through the API of a DNS hosting Provider.
type DyndnsClient struct {
	Base
	InstanceID  uint   `json:"instance_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	InterfaceID uint   `json:"interface_id"`
	// Provider is a fwconfig.DNSProviders name.
	Provider string `json:"provider"`
	// ProviderSettings are the provider's fields, secrets included; never
	// sent back. They are written through Settings.
	ProviderSettings StringMap `json:"-"`
	// Settings are, written, the fields to store (an empty secret keeps
	// the stored one) and, read, the fields that are not secret.
	Settings map[string]string `gorm:"-" json:"provider_settings"`
	// SecretsSet lists the secret fields that have a stored value.
	SecretsSet    []string `gorm:"-" json:"provider_secrets_set"`
	Server        string   `json:"server"`
	Zone          string   `json:"zone"`
	TsigName      string   `json:"tsig_name"`
	TsigAlgorithm string   `json:"tsig_algorithm"`
	// TsigSecret is set through NewTsigSecret and never sent back.
	TsigSecret     string `json:"-"`
	RetryInterval  int    `json:"retry_interval"`
	VerifyInterval int    `json:"verify_interval"`
	// NewTsigSecret replaces the stored secret when not empty.
	NewTsigSecret string `gorm:"-" json:"tsig_secret,omitempty"`
	HasTsigSecret bool   `gorm:"-" json:"has_tsig_secret"`
}

// Certificate is a TLS certificate the agent gets from an ACME CA (Let's
// Encrypt) and renews. The CA's HTTP-01 requests come in on Interface.
type Certificate struct {
	Base
	InstanceID  uint       `json:"instance_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Enabled     bool       `json:"enabled"`
	Domains     StringList `json:"domains"`
	Email       string     `json:"email"`
	// Ca is a fwconfig.ACMECAs name or an ACME directory URL.
	Ca          string `json:"ca"`
	KeyType     string `json:"key_type"`
	Challenge   string `json:"challenge"`
	InterfaceID uint   `json:"interface_id"`
}

// DyndnsRecord is a record a DyndnsClient maintains. A/AAAA without Value
// follow the interface; TXT without Value holds the last update time.
type DyndnsRecord struct {
	Base
	ClientID    uint   `json:"client_id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Ttl         int    `json:"ttl"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// IpList is an address list the agent downloads (fwconfig.IPList). Rules
// use it by name as "@name" in their address lists.
type IpList struct {
	Base
	Name        string `gorm:"uniqueIndex" json:"name"`
	Description string `json:"description"`
	Source      string `json:"source"` // fwconfig.IPList*
	FolderID    *uint  `json:"folder_id"`
	Url         string `json:"url"`
	Username    string `json:"username"`
	// Password and ApiKey are set through NewPassword and NewApiKey and
	// never sent back.
	Password string `json:"-"`
	ApiKey   string `json:"-"`
	// NewPassword and NewApiKey replace the stored secret when not empty.
	NewPassword string `gorm:"-" json:"password,omitempty"`
	NewApiKey   string `gorm:"-" json:"api_key,omitempty"`
	HasPassword bool   `gorm:"-" json:"has_password"`
	HasApiKey   bool   `gorm:"-" json:"has_api_key"`
}

// Task runs on the firewall on a cron schedule (fwconfig.Task): it
// downloads IpListID, or runs Command as the agent's console user.
type Task struct {
	Base
	Name        string `gorm:"uniqueIndex" json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Schedule    string `json:"schedule"`
	Kind        string `json:"kind"` // fwconfig.Task*
	IpListID    *uint  `json:"ip_list_id"`
	Command     string `json:"command"`
	Timeout     int    `json:"timeout"` // seconds; 0 is the default
}

// KnownInterface is a physical interface the agent has reported
// (web/nics.go). A new one is imported into the default instance once, so
// deleting it there sticks.
type KnownInterface struct {
	Name      string    `gorm:"primaryKey" json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Deployment is one push to the agent.
type Deployment struct {
	Base
	Generation int64  `json:"generation"`
	Username   string `json:"username"`
	// Status: applied, pending, confirmed, rolled_back, failed.
	Status   string `json:"status"`
	Message  string `json:"message"`
	Document string `json:"-"`
	// DocHash is docHash of the unredacted document; empty on rows older
	// than the column.
	DocHash string `json:"-"`
	Log     string `json:"log"`
	// Instances lists the instances built from the database; the others
	// kept what was deployed. Empty: all of them.
	Instances StringList `json:"instances"`
}

// All lists every model; a dbmigrate test checks that the migrated schema
// has a column for every field.
func All() []any {
	return []any{
		&User{}, &Settings{}, &Instance{}, &InterfaceZone{}, &Interface{}, &WgPeer{}, &Link{},
		&Route{}, &Rule{}, &NatRule{}, &IpamPrefix{}, &IpamAddress{}, &DnsZone{}, &DnsRecord{}, &Deployment{},
		&AddressObject{}, &DnsSoaTemplate{}, &DnsDnssecPolicy{}, &DnsTemplate{}, &KnownInterface{},
		&DyndnsClient{}, &DyndnsRecord{}, &Certificate{}, &IpList{}, &Task{}, &Service{}, &ObjectFolder{}, &Role{}, &RoleMember{}, &RoleInstance{},
	}
}
