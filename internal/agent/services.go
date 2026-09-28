// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

// servicePort is a port of a transport protocol, as /etc/services lists it.
type servicePort struct {
	proto string // tcp, udp, sctp
	port  uint16
}

// serviceNames are the service names of /etc/services, read on first use;
// empty when it can't be read.
var serviceNames = sync.OnceValue(func() map[servicePort]string {
	f, err := os.Open("/etc/services")
	if err != nil {
		return nil
	}
	defer f.Close()
	return parseServices(f)
})

// serviceName is the name of a port of protocol proto, or "" when
// /etc/services doesn't name it.
func serviceName(proto string, port uint16) string {
	if port == 0 {
		return ""
	}
	return serviceNames()[servicePort{proto, port}]
}

// parseServices reads services(5): "name port/protocol [aliases] [# comment]".
// A port listed more than once keeps its first name.
func parseServices(r io.Reader) map[servicePort]string {
	m := map[servicePort]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		portStr, proto, ok := strings.Cut(fields[1], "/")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || port == 0 {
			continue
		}
		k := servicePort{strings.ToLower(proto), uint16(port)}
		if _, dup := m[k]; !dup {
			m[k] = fields[0]
		}
	}
	return m
}
