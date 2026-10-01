// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package fwconfig

import "slices"

// ProviderRFC2136 sends RFC 2136 UPDATEs to a nameserver (Server, TSIG).
// It is the default when a DNS update client names no provider.
const ProviderRFC2136 = "rfc2136"

// DNSProvider is a DNS hosting service a DNS update client can keep
// records at, through its API (a libdns provider in the agent).
type DNSProvider struct {
	Name   string             `json:"name"`
	Label  string             `json:"label"`
	Fields []DNSProviderField `json:"fields"`
}

// DNSProviderField is a setting of a provider. Key is the libdns
// provider's JSON field name. Secret fields never reach the browser.
type DNSProviderField struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Secret      bool   `json:"secret,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

func token(key, label string) DNSProviderField {
	return DNSProviderField{Key: key, Label: label, Secret: true, Required: true}
}

// DNSProviders are the providers, RFC 2136 first.
var DNSProviders = []DNSProvider{
	{Name: ProviderRFC2136, Label: "RFC 2136 (own nameserver)", Fields: []DNSProviderField{}},
	{Name: "bunny", Label: "Bunny DNS", Fields: []DNSProviderField{token("access_key", "API access key")}},
	{Name: "cloudflare", Label: "Cloudflare", Fields: []DNSProviderField{
		token("api_token", "API token"),
		{Key: "zone_token", Label: "Zone read token", Secret: true, Hint: "Only when the API token is limited to one zone: a token with Zone:Read on all zones."},
	}},
	{Name: "desec", Label: "deSEC", Fields: []DNSProviderField{token("token", "API token")}},
	{Name: "easydns", Label: "easyDNS", Fields: []DNSProviderField{
		token("api_token", "API token"),
		token("api_key", "API key"),
		{Key: "api_url", Label: "API URL", Placeholder: "https://rest.easydns.net"},
	}},
	{Name: "gandi", Label: "Gandi", Fields: []DNSProviderField{token("bearer_token", "Personal access token")}},
	{Name: "glesys", Label: "GleSYS", Fields: []DNSProviderField{
		{Key: "project", Label: "Project", Required: true, Placeholder: "CL12345"},
		token("api_key", "API key"),
	}},
	{Name: "godaddy", Label: "GoDaddy", Fields: []DNSProviderField{
		{Key: "api_token", Label: "API key and secret", Secret: true, Required: true, Placeholder: "key:secret"},
	}},
	{Name: "hetzner", Label: "Hetzner DNS", Fields: []DNSProviderField{token("auth_api_token", "API token")}},
	{Name: "loopia", Label: "Loopia", Fields: []DNSProviderField{
		{Key: "username", Label: "API user", Required: true, Placeholder: "user@loopiaapi"},
		token("password", "API password"),
		{Key: "customer", Label: "Customer", Hint: "Resellers only: the customer number the zone belongs to."},
	}},
	{Name: "namecheap", Label: "Namecheap", Fields: []DNSProviderField{
		{Key: "user", Label: "API user", Required: true},
		token("api_key", "API key"),
		{Key: "client_ip", Label: "Client IP", Placeholder: "203.0.113.7", Hint: "The address allowed in Namecheap's API settings. Empty: looked up on each start."},
	}},
	{Name: "namesilo", Label: "NameSilo", Fields: []DNSProviderField{token("api_token", "API key")}},
	{Name: "netcup", Label: "netcup", Fields: []DNSProviderField{
		{Key: "customer_number", Label: "Customer number", Required: true},
		token("api_key", "API key"),
		token("api_password", "API password"),
	}},
	{Name: "njalla", Label: "Njalla", Fields: []DNSProviderField{token("api_token", "API token")}},
	{Name: "ovh", Label: "OVHcloud", Fields: []DNSProviderField{
		{Key: "endpoint", Label: "Endpoint", Required: true, Placeholder: "ovh-eu"},
		token("application_key", "Application key"),
		token("application_secret", "Application secret"),
		token("consumer_key", "Consumer key"),
	}},
	{Name: "porkbun", Label: "Porkbun", Fields: []DNSProviderField{
		token("api_key", "API key"),
		token("api_secret_key", "Secret API key"),
	}},
}

// FindDNSProvider returns the provider called name ("" is RFC 2136), or nil.
func FindDNSProvider(name string) *DNSProvider {
	if name == "" {
		name = ProviderRFC2136
	}
	i := slices.IndexFunc(DNSProviders, func(p DNSProvider) bool { return p.Name == name })
	if i < 0 {
		return nil
	}
	return &DNSProviders[i]
}

// Field returns the provider's field called key, or nil.
func (p *DNSProvider) Field(key string) *DNSProviderField {
	i := slices.IndexFunc(p.Fields, func(f DNSProviderField) bool { return f.Key == key })
	if i < 0 {
		return nil
	}
	return &p.Fields[i]
}
