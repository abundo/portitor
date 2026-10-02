// SPDX-FileCopyrightText: 2026 The Portitor contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abundo/portitor/internal/wgkeys"
	"github.com/abundo/portitor/models"
)

func TestWgImport(t *testing.T) {
	env := newEnv(t)
	inst := env.create("/api/instances", map[string]any{"name": "main"})
	priv, pub, _ := wgkeys.Generate()
	_, peerPub, _ := wgkeys.Generate()
	conf := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.99.0.1/24, fd00:99::1\nListenPort = 51821\nDNS = 1.1.1.1\n\n# phone\n[Peer]\nPublicKey = " + peerPub + "\nAllowedIPs = 10.99.0.2/32\nPersistentKeepalive = 25\n"
	body := map[string]any{"instance_id": inst, "name": "wg5", "config": conf}
	rec := env.do("POST", "/api/wg/import", body)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), priv) || !strings.Contains(rec.Body.String(), "dns") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var ifc models.Interface
	env.srv.db.Where("name = ?", "wg5").First(&ifc)
	if ifc.WgPrivateKey != priv || ifc.WgPublicKey != pub || ifc.WgListenPort != 51821 || len(ifc.Addresses) != 2 || ifc.Addresses[1] != "fd00:99::1/128" {
		t.Fatalf("interface %+v", ifc)
	}
	var peers []models.WgPeer
	env.srv.db.Where("interface_id = ?", ifc.ID).Find(&peers)
	if len(peers) != 1 || peers[0].Name != "phone" || peers[0].Keepalive != 25 {
		t.Fatalf("peers %+v", peers)
	}
	if rec := env.do("POST", "/api/wg/import", body); rec.Code != http.StatusConflict {
		t.Errorf("existing interface imported without overwrite: %d", rec.Code)
	}
	body["overwrite"] = true
	if rec := env.do("POST", "/api/wg/import", body); rec.Code != http.StatusOK {
		t.Fatalf("overwrite: %d %s", rec.Code, rec.Body)
	}
	var n int64
	env.srv.db.Model(&models.WgPeer{}).Where("interface_id = ?", ifc.ID).Count(&n)
	if n != 1 {
		t.Errorf("overwrite left %d peers", n)
	}
	body["config"] = "[Interface]\nPrivateKey = nope\n"
	if rec := env.do("POST", "/api/wg/import", body); rec.Code != http.StatusBadRequest {
		t.Errorf("bad key accepted: %d", rec.Code)
	}
}
