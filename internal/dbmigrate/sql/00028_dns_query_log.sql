-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- DNS query logging, with filters on clients, names and query types.
ALTER TABLE instances ADD COLUMN dns_query_log BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN dns_query_log_clients TEXT NOT NULL DEFAULT '[]';
ALTER TABLE instances ADD COLUMN dns_query_log_names TEXT NOT NULL DEFAULT '[]';
ALTER TABLE instances ADD COLUMN dns_query_log_types TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE instances DROP COLUMN dns_query_log_types;
ALTER TABLE instances DROP COLUMN dns_query_log_names;
ALTER TABLE instances DROP COLUMN dns_query_log_clients;
ALTER TABLE instances DROP COLUMN dns_query_log;
