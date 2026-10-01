-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- DNS update clients keep records through a DNS hosting provider's API as
-- well as by RFC 2136. provider_settings is a JSON object of the
-- provider's fields, secrets included; the server is for RFC 2136 only.
-- +goose Up
ALTER TABLE dyndns_clients ADD COLUMN provider TEXT NOT NULL DEFAULT 'rfc2136';
ALTER TABLE dyndns_clients ADD COLUMN provider_settings TEXT NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE dyndns_clients DROP COLUMN provider_settings;
ALTER TABLE dyndns_clients DROP COLUMN provider;
