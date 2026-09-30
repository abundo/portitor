-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- BIND's dnssec-validation for the instance's DNS server: 'auto' or 'no'.
ALTER TABLE instances ADD COLUMN dns_dnssec_validation TEXT NOT NULL DEFAULT 'auto';

-- +goose Down
ALTER TABLE instances DROP COLUMN dns_dnssec_validation;
