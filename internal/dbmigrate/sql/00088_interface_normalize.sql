-- SPDX-FileCopyrightText: 2026 The Portitor contributors
-- SPDX-License-Identifier: AGPL-3.0-or-later

-- +goose Up
-- MSS clamping of the forwarded TCP SYNs through an interface (0: by the
-- route's MTU) and its strict reverse path check
-- (fwconfig.Interface.MSSClamp, RPF).
ALTER TABLE interfaces ADD COLUMN mss_clamp BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE interfaces ADD COLUMN mss_clamp_value INTEGER NOT NULL DEFAULT 0;
ALTER TABLE interfaces ADD COLUMN rpf BOOLEAN NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN rpf;
ALTER TABLE interfaces DROP COLUMN mss_clamp_value;
ALTER TABLE interfaces DROP COLUMN mss_clamp;
