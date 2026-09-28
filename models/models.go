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
	"time"
)

type Base struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (b *Base) GetID() uint   { return b.ID }
func (b *Base) SetID(id uint) { b.ID = id }

// StringList is stored as a JSON array (jsonb in Postgres).
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

func (StringList) GormDataType() string { return "jsonb" }

type User struct {
	Base
	Username     string `gorm:"uniqueIndex" json:"username"`
	FullName     string `json:"full_name"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	// TokenVersion invalidates issued sessions when bumped (password
	// change, logout everywhere).
	TokenVersion int `json:"-"`
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

	DnsEnabled         bool       `json:"dns_enabled"`
	DnsForwarders      StringList `json:"dns_forwarders"`
	DnsForwardFromDhcp bool       `json:"dns_forward_from_dhcp"`
	DnsForwardMode     string     `json:"dns_forward_mode"` // fwconfig.Forward*
	DnsAllowRecursion  StringList `json:"dns_allow_recursion"`

	DhcpEnabled    bool   `json:"dhcp_enabled"`
	DhcpDomainName string `json:"dhcp_domain_name"`
	DhcpLeaseTime  int    `json:"dhcp_lease_time"`
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
	InstanceID   uint       `json:"instance_id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	Description  string     `json:"description"`
	Enabled      bool       `json:"enabled"`
	Parent       string     `json:"parent"`
	VlanID       int        `json:"vlan_id"`
	Members      StringList `json:"members"`
	Mtu          int        `json:"mtu"`
	Ipv4Mode     string     `json:"ipv4_mode"`
	Ipv6AcceptRA bool       `gorm:"column:ipv6_accept_ra" json:"ipv6_accept_ra"`
	// DnsListen makes the instance's DNS server answer on this interface.
	DnsListen bool `json:"dns_listen"`

	WgPrivateKey string `json:"-"`
	WgPublicKey  string `json:"wg_public_key"`
	WgListenPort int    `json:"wg_listen_port"`
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
	Keepalive    int        `json:"keepalive"`
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
	// Kind is empty for a rule or RuleKindComment for a comment row, whose
	// text is Description; comments only annotate the list.
	Kind string `json:"kind"`
	// InInterfaces and OutInterfaces hold interface and interface zone
	// names of the instance; empty matches any.
	InInterfaces  StringList `json:"in_interfaces"`
	OutInterfaces StringList `json:"out_interfaces"`
	Family        string     `json:"family"`
	Protocol      string     `json:"protocol"`
	SrcAddrs      StringList `json:"src_addrs"`
	DstAddrs      StringList `json:"dst_addrs"`
	DstPorts      string     `json:"dst_ports"`
	Action        string     `json:"action"`
	Log           bool       `json:"log"`
	Enabled       bool       `json:"enabled"`
	Description   string     `json:"description"`
}

// RuleKindComment marks a Rule that is a comment row between rules.
const RuleKindComment = "comment"

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
}

// IpamAddress is a single address. With InterfaceID it is configured on
// that firewall interface (prefix length from the enclosing IpamPrefix).
// With DnsName it gets an A/AAAA record; with Mac also a DHCP reservation.
type IpamAddress struct {
	Base
	InstanceID  uint   `json:"instance_id"`
	Address     string `json:"address"`
	InterfaceID *uint  `json:"interface_id"`
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
	Name           string     `json:"name"`
	SoaTemplateID  uint       `json:"soa_template_id"`
	DefaultTtl     int64      `json:"default_ttl"`
	DnssecPolicyID *uint      `json:"dnssec_policy_id"`
	Nameservers    StringList `json:"nameservers"`
	Description    string     `json:"description"`
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
	Document string `gorm:"type:jsonb" json:"-"`
	// DocHash is docHash of the unredacted document; empty on rows older
	// than the column.
	DocHash string `json:"-"`
	Log     string `json:"log"`
}

// All lists every model, for AutoMigrate in tests (production uses the
// goose migrations).
func All() []any {
	return []any{
		&User{}, &Settings{}, &Instance{}, &InterfaceZone{}, &Interface{}, &WgPeer{}, &Link{},
		&Route{}, &Rule{}, &NatRule{}, &IpamPrefix{}, &IpamAddress{}, &DnsZone{}, &DnsRecord{}, &Deployment{},
		&AddressObject{}, &DnsSoaTemplate{}, &DnsDnssecPolicy{}, &DnsTemplate{}, &KnownInterface{},
	}
}
