-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The DNS update client whose provider writes a DNS-01 challenge's TXT
-- records.
ALTER TABLE certificates ADD COLUMN dyndns_client_id INTEGER REFERENCES dyndns_clients(id);

-- +goose Down
ALTER TABLE certificates DROP COLUMN dyndns_client_id;
