-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The DNS server (named) always runs. An instance that had it off and
-- forwarded nowhere resolves from the root servers.
UPDATE instances SET dns_upstream = 'root' WHERE dns_upstream = 'forward' AND dns_forwarders = '[]';
ALTER TABLE instances DROP COLUMN dns_enabled;

-- +goose Down
ALTER TABLE instances ADD COLUMN dns_enabled BOOLEAN NOT NULL DEFAULT true;
