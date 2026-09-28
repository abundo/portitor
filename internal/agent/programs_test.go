// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/fwconfig"
)

func fakeInstalled(t *testing.T, missing ...string) {
	t.Helper()
	orig := lookPath
	lookPath = func(name string) (string, error) {
		for _, m := range missing {
			if name == m {
				return "", exec.ErrNotFound
			}
		}
		return "/usr/sbin/" + name, nil
	}
	t.Cleanup(func() { lookPath = orig })
}

func TestCheckPrograms(t *testing.T) {
	doc := fwconfig.SampleDocument()
	exp := doc.Expand()

	fakeInstalled(t)
	if err := checkPrograms(&exp); err != nil {
		t.Fatalf("all installed: %v", err)
	}

	fakeInstalled(t, "named", "radvd")
	err := checkPrograms(&exp)
	if err == nil || !strings.Contains(err.Error(), "named, for DNS server") || !strings.Contains(err.Error(), "radvd") {
		t.Fatalf("missing named/radvd: %v", err)
	}

	// Not needed when the instance doesn't use it.
	for i := range exp.Instances {
		exp.Instances[i].DNS.Enabled = false
		exp.Instances[i].RA = nil
	}
	if err := checkPrograms(&exp); err != nil {
		t.Fatalf("DNS and RA off: %v", err)
	}
}

func TestProgramStatus(t *testing.T) {
	fakeInstalled(t, "kea-dhcp6")
	doc := fwconfig.SampleDocument()
	for _, p := range programStatus(&doc) {
		if (p.Path == "") != (p.Name == "kea-dhcp6") {
			t.Errorf("%s: path %q", p.Name, p.Path)
		}
		if !p.Needed {
			t.Errorf("%s: sample document needs it", p.Name)
		}
	}
	for _, p := range programStatus(nil) {
		if p.Needed {
			t.Errorf("%s: needed without a document", p.Name)
		}
	}
}
