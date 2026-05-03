-- Copyright (c) 2026 Cloudflare, Inc.
-- Licensed under the Apache 2.0 license found in the LICENSE file or at:
--     https://opensource.org/licenses/Apache-2.0

-- Per-cron last-fired watermark. Written at the START of each cron iteration
-- (not on success) so a hung run is still observable from /admin/stats.
--
-- Replaces the `MAX(inbound_peers.last_pulled_ts)` proxy that masks a healthy
-- cron whenever every upstream peer is currently failing.
--
-- `last_run_at` is epoch milliseconds (INTEGER) — directly usable by JS
-- consumers without a parse step and unambiguous across timezones.
CREATE TABLE cron_runs (
    name TEXT PRIMARY KEY,
    last_run_at INTEGER NOT NULL
);
