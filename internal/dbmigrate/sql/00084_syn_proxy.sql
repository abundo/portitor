-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- A forward accept rule's SYN proxy (fwconfig.SynProxy): the TCP handshake
-- answered with SYN cookies on the server's behalf. syn_proxy_mss 0 is
-- 1460 (IPv4; 20 less for IPv6).
ALTER TABLE rules ADD COLUMN syn_proxy BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rules ADD COLUMN syn_proxy_mss INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rules ADD COLUMN syn_proxy_wscale INTEGER NOT NULL DEFAULT 7;

-- +goose Down
ALTER TABLE rules DROP COLUMN syn_proxy_wscale;
ALTER TABLE rules DROP COLUMN syn_proxy_mss;
ALTER TABLE rules DROP COLUMN syn_proxy;
