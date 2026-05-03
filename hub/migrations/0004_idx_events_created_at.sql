-- Copyright (c) 2026 Cloudflare, Inc.
-- Licensed under the Apache 2.0 license found in the LICENSE file or at:
--     https://opensource.org/licenses/Apache-2.0

-- Index `events.created_at` so /admin/stats can window the
-- "events ingested in the last 24h / 7d" counters by ingest time
-- instead of the upstream MISP `events.date` (YYYY-MM-DD). When peers
-- backfill stale-dated events the upstream `date` lands them in the
-- wrong day's bucket; `created_at` is the local-ingest semantic the
-- at-a-glance dashboard wants.
--
-- Other event-time queries (peers.events_pulled_24h, triage 24h slice,
-- untagged-15m pre-filter) intentionally stay on `idx_events_date` —
-- those want upstream-date semantics, or use `date` as a bounded
-- pre-filter for a non-indexed predicate. See `routes/admin/stats.ts`.
CREATE INDEX idx_events_created_at ON events(created_at);
