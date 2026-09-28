// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package netobj

import (
	"regexp"
	"strings"

	"github.com/abundo/portitor/internal/fwconfig"
	"github.com/abundo/portitor/models"
)

// Custom service names are lower case, like the built-in ones, and start
// with a letter, so they can never be read as a port or range.
var serviceNameRe = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)

// ValidServiceName reports whether s can name a custom service: it must not
// be a built-in name either.
func ValidServiceName(s string) bool {
	_, builtin := fwconfig.ServicePort(s)
	return serviceNameRe.MatchString(s) && !builtin && s != "any"
}

// Services maps custom service names (models.Service) to their port lists.
// Port lists may name them wherever they take built-in names; portitor-web
// expands them when it builds the document, so the agent only ever sees
// numbers, ranges and built-in names.
type Services map[string]string

func NewServices(list []models.Service) Services {
	s := Services{}
	for _, svc := range list {
		s[svc.Name] = svc.Ports
	}
	return s
}

// ExpandPorts replaces the custom service names in a port list by their
// ports and checks the result (fwconfig.ParsePorts). A list without custom
// names comes back as it is, others with their entries joined by ", ".
func (s Services) ExpandPorts(ports string) (string, error) {
	var out []string
	expanded := false
	for _, part := range strings.Split(ports, ",") {
		part = strings.TrimSpace(part)
		if p, ok := s[strings.ToLower(part)]; ok {
			out = append(out, p)
			expanded = true
		} else {
			out = append(out, part)
		}
	}
	res := ports
	if expanded {
		res = strings.Join(out, ", ")
	}
	if _, err := fwconfig.ParsePorts(res); err != nil {
		return "", err
	}
	return res, nil
}
