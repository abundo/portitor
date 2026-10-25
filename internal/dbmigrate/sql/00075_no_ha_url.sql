-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A firewall's agent URL is its address on the network, which its HA peer
-- uses too; portitor-config reaches its own agent by its agent_url. The HA
-- URL was that address where the agent URL was loopback.
UPDATE firewalls SET agent_url = ha_url WHERE ha_url != '';
ALTER TABLE firewalls DROP COLUMN ha_url;

-- +goose Down
ALTER TABLE firewalls ADD COLUMN ha_url TEXT NOT NULL DEFAULT '';
