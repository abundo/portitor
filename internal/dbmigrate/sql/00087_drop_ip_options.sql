-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- Drop the IPv4 packets with IP options to the firewall and through it, in
-- every instance (fwconfig.Instance.DropIPOptions).
ALTER TABLE settings ADD COLUMN drop_ip_options_input BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE settings ADD COLUMN drop_ip_options_forward BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE settings DROP COLUMN drop_ip_options_forward;
ALTER TABLE settings DROP COLUMN drop_ip_options_input;
