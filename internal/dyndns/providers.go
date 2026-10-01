// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package dyndns

import (
	"encoding/json"
	"fmt"

	"github.com/libdns/bunny"
	"github.com/libdns/cloudflare"
	"github.com/libdns/desec"
	"github.com/libdns/easydns"
	"github.com/libdns/gandi"
	"github.com/libdns/glesys"
	"github.com/libdns/godaddy"
	"github.com/libdns/hetzner"
	"github.com/libdns/loopia"
	"github.com/libdns/namecheap"
	"github.com/libdns/namesilo"
	"github.com/libdns/netcup"
	"github.com/libdns/njalla"
	"github.com/libdns/ovh"
	"github.com/libdns/porkbun"
)

// providers make an empty libdns provider for each fwconfig.DNSProviders
// name but RFC 2136. A provider's settings are its JSON fields.
var providers = map[string]func() Provider{
	"bunny":      func() Provider { return new(bunny.Provider) },
	"cloudflare": func() Provider { return new(cloudflare.Provider) },
	"desec":      func() Provider { return new(desec.Provider) },
	"easydns":    func() Provider { return new(easydns.Provider) },
	"gandi":      func() Provider { return new(gandi.Provider) },
	"glesys":     func() Provider { return new(glesys.Provider) },
	"godaddy":    func() Provider { return new(godaddy.Provider) },
	"hetzner":    func() Provider { return new(hetzner.Provider) },
	"loopia":     func() Provider { return new(loopia.Provider) },
	"namecheap":  func() Provider { return new(namecheap.Provider) },
	"namesilo":   func() Provider { return new(namesilo.Provider) },
	"netcup":     func() Provider { return new(netcup.Provider) },
	"njalla":     func() Provider { return new(njalla.Provider) },
	"ovh":        func() Provider { return new(ovh.Provider) },
	"porkbun":    func() Provider { return new(porkbun.Provider) },
}

// NewProvider returns the libdns provider called name with its settings.
func NewProvider(name string, settings map[string]string) (Provider, error) {
	mk := providers[name]
	if mk == nil {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	p := mk()
	b, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, p); err != nil {
		return nil, fmt.Errorf("%s settings: %w", name, err)
	}
	return p, nil
}
