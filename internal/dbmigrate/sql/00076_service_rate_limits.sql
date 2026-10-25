-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- The DNS, DHCP and NTP servers may police what comes in to them
-- (fwconfig.ServiceRateLimit) with a rate limit of their own, the one
-- whose service is theirs. Every instance gets one for each, 1 Mbit/s, on,
-- as a new one does (seedInstance).
ALTER TABLE instances ADD COLUMN dns_rate_limit BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN dhcp_rate_limit BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE instances ADD COLUMN ntp_rate_limit BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rate_limits ADD COLUMN service TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX rate_limits_service ON rate_limits (instance_id, service) WHERE service != '';
INSERT INTO rate_limits (instance_id, name, description, rate, per, unit, connections, service)
SELECT i.id,
    s.name || CASE WHEN EXISTS (SELECT 1 FROM rate_limits r WHERE r.instance_id = i.id AND r.name = s.name)
        THEN ' (service)' ELSE '' END,
    s.description, 1, 'second', 'mbit', true, s.service
FROM instances i, (
    SELECT 'dns' AS service, 'dns server' AS name, 'What comes in to the DNS server' AS description
    UNION ALL SELECT 'dhcp', 'dhcp server', 'What comes in to the DHCP server'
    UNION ALL SELECT 'ntp', 'ntp server', 'What comes in to the NTP server'
) s;
UPDATE instances SET dns_rate_limit = true, dhcp_rate_limit = true, ntp_rate_limit = true;

-- +goose Down
DELETE FROM rate_limits WHERE service != '';
DROP INDEX rate_limits_service;
ALTER TABLE rate_limits DROP COLUMN service;
ALTER TABLE instances DROP COLUMN ntp_rate_limit;
ALTER TABLE instances DROP COLUMN dhcp_rate_limit;
ALTER TABLE instances DROP COLUMN dns_rate_limit;
