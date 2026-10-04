-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- NTP (chrony): whether the instance runs it, its time sources
-- (fwconfig.NTPServer as JSON) and the client prefixes it answers; the
-- interfaces it answers on have ntp_serve.
ALTER TABLE instances ADD COLUMN ntp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN ntp_servers TEXT NOT NULL DEFAULT '[]';
ALTER TABLE instances ADD COLUMN ntp_allow TEXT NOT NULL DEFAULT '[]';
ALTER TABLE interfaces ADD COLUMN ntp_serve BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN ntp_serve;
ALTER TABLE instances DROP COLUMN ntp_allow;
ALTER TABLE instances DROP COLUMN ntp_servers;
ALTER TABLE instances DROP COLUMN ntp_enabled;
