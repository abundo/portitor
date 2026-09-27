-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- DNS templates, shared by all instances: a zone's template gives it its
-- SOA (from an SOA template), default TTL, apex NS records and optionally a
-- DNSSEC policy. A zone without a template gets a built-in SOA/NS pointing
-- at localhost.
CREATE TABLE dns_soa_templates (
    id         BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    name       TEXT NOT NULL UNIQUE,
    mname      TEXT NOT NULL,
    rname      TEXT NOT NULL,
    refresh    BIGINT NOT NULL DEFAULT 86400,
    retry      BIGINT NOT NULL DEFAULT 7200,
    expire     BIGINT NOT NULL DEFAULT 3600000,
    minimum    BIGINT NOT NULL DEFAULT 3600
);

CREATE TABLE dns_dnssec_policies (
    id                         BIGSERIAL PRIMARY KEY,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    name                       TEXT NOT NULL UNIQUE,
    ksk_lifetime               TEXT NOT NULL DEFAULT '',
    ksk_algorithm              TEXT NOT NULL,
    zsk_lifetime               TEXT NOT NULL DEFAULT '',
    zsk_algorithm              TEXT NOT NULL,
    purge_keys                 TEXT NOT NULL DEFAULT '',
    signatures_validity        TEXT NOT NULL DEFAULT '',
    signatures_validity_dnskey TEXT NOT NULL DEFAULT '',
    signatures_refresh         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE dns_templates (
    id               BIGSERIAL PRIMARY KEY,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    name             TEXT NOT NULL UNIQUE,
    soa_template_id  BIGINT NOT NULL REFERENCES dns_soa_templates(id) ON DELETE RESTRICT,
    default_ttl      BIGINT NOT NULL DEFAULT 3600,
    dnssec_policy_id BIGINT REFERENCES dns_dnssec_policies(id) ON DELETE RESTRICT,
    nameservers      JSONB NOT NULL DEFAULT '[]',
    description      TEXT NOT NULL DEFAULT ''
);

ALTER TABLE dns_zones ADD COLUMN dns_template_id BIGINT REFERENCES dns_templates(id) ON DELETE RESTRICT;

-- +goose Down
ALTER TABLE dns_zones DROP COLUMN dns_template_id;
DROP TABLE dns_templates;
DROP TABLE dns_dnssec_policies;
DROP TABLE dns_soa_templates;
