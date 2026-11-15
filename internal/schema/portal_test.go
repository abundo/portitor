// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package schema

import "testing"

func TestLoadPortal(t *testing.T) {
	root, err := LoadPortal()
	if err != nil {
		t.Fatal(err)
	}
	if root.Module() != PortalModule || root.Child("firewall") == nil || !root.Child("user").Child("password-hash").Secret() {
		t.Fatal("portal schema incomplete")
	}
}
