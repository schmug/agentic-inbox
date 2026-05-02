// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * GET /admin/stats — at-a-glance hub operational health.
 *
 * Single JSON snapshot for an operator. Covers:
 *   - org & event counts (with 24h / 7d slices)
 *   - corroboration row count + promoted-to-destroylist count
 *   - destroylist sizes per sharing group
 *   - inbound peers: last pull time, last error, events pulled in last 24h
 *   - triage health: % of last-24h events that got LLM tags + count of
 *     events still untagged 15m after ingest (queue-backup smoke signal)
 *   - cron last-run proxy
 *
 * Index discipline. All counts come off existing D1 indexes from
 * 0001_schema.sql / 0002_inbound_sync.sql; no new migrations are
 * introduced by this endpoint:
 *
 *   - `idx_events_date`           drives the 24h / 7d windows on `events`.
 *     Note: `events.date` is the upstream MISP event date (YYYY-MM-DD),
 *     not local ingest time. We accept the coarseness — for an at-a-glance
 *     dashboard it's a close-enough proxy and it's the only indexed time
 *     column on `events`. Adding a `created_at` index would be a separate
 *     migration; that's a follow-up, not part of this endpoint.
 *   - `idx_events_source_peer`    drives per-peer events_pulled_24h.
 *   - `idx_corroboration_sharing_group` drives the destroylist groupby.
 *
 * Where a query needs a non-indexed predicate (e.g. the 15-minute
 * `created_at` filter for stuck-in-triage events), it is gated behind an
 * indexed pre-filter (`date >= today-1`) so the scan is bounded to a
 * single day's slice rather than the full table.
 *
 * `cron.last_run_at` is a proxy: there is no cron-history table in the
 * schema today. We surface `MAX(last_pulled_ts)` across inbound peers as
 * the closest signal — if the cron is alive AND any peer is healthy, this
 * advances every 5 minutes. A peer-pull failure can mask a healthy cron;
 * a real cron-run-log is filed as a follow-up.
 */

import { Hono } from "hono";
import { requireAdmin, type AdminContext } from "../../lib/admin-auth";
import { PROMOTION_SCORE, PROMOTION_CONTRIBUTORS } from "../../lib/aggregate";

export const adminStatsRoutes = new Hono<AdminContext>();

adminStatsRoutes.use("*", requireAdmin);

interface CountRow {
	n: number;
}

adminStatsRoutes.get("/stats", async (c) => {
	const db = c.env.DB;

	// --- orgs -----------------------------------------------------------
	const orgsTotal = (await db.prepare(`SELECT COUNT(*) AS n FROM orgs`).first<CountRow>())?.n ?? 0;

	// "active" = has authored at least one event in the last 7d. Uses
	// idx_events_date; date is upstream YYYY-MM-DD, see file-level note.
	const activeOrgs = (await db
		.prepare(
			`SELECT COUNT(DISTINCT orgc_uuid) AS n
			 FROM events
			 WHERE date >= date('now', '-7 days')`,
		)
		.first<CountRow>())?.n ?? 0;

	// --- events ---------------------------------------------------------
	const eventsTotal = (await db.prepare(`SELECT COUNT(*) AS n FROM events`).first<CountRow>())?.n ?? 0;
	const eventsLast24h = (await db
		.prepare(
			`SELECT COUNT(*) AS n FROM events WHERE date >= date('now', '-1 day')`,
		)
		.first<CountRow>())?.n ?? 0;

	// --- corroboration --------------------------------------------------
	const corroborationRows = (await db
		.prepare(`SELECT COUNT(*) AS n FROM corroboration`)
		.first<CountRow>())?.n ?? 0;
	// Use the same predicate `aggregate.ts` uses for promotion. Imported
	// rather than re-declared so a threshold change in one place can never
	// drift from the other.
	const corroborationPromoted = (await db
		.prepare(
			`SELECT COUNT(*) AS n FROM corroboration
			 WHERE score >= ?1 AND contributor_count >= ?2`,
		)
		.bind(PROMOTION_SCORE, PROMOTION_CONTRIBUTORS)
		.first<CountRow>())?.n ?? 0;

	// --- destroylist size per sharing group -----------------------------
	const destroyRows = await db
		.prepare(
			`SELECT sg.uuid AS uuid, sg.name AS name, COUNT(c.id) AS size
			 FROM sharing_groups sg
			 LEFT JOIN corroboration c
			   ON c.sharing_group_uuid = sg.uuid
			   AND c.score >= ?1
			   AND c.contributor_count >= ?2
			 GROUP BY sg.uuid, sg.name
			 ORDER BY sg.name`,
		)
		.bind(PROMOTION_SCORE, PROMOTION_CONTRIBUTORS)
		.all<{ uuid: string; name: string; size: number }>();
	const destroylistBySharingGroup = (destroyRows.results ?? []).map((r) => ({
		uuid: r.uuid,
		name: r.name,
		size: r.size,
	}));

	// --- peers ----------------------------------------------------------
	// Two-step: (1) list peers, (2) for each peer count events_pulled_24h
	// off idx_events_source_peer + date predicate. Fan-out is bounded by
	// the peer count (small — operator config), so this is fine.
	const peerRows = await db
		.prepare(
			`SELECT ib.uuid AS inbound_uuid, p.name AS name,
			        ib.last_pulled_ts AS last_pulled_at,
			        ib.last_error AS last_error
			 FROM inbound_peers ib JOIN peers p ON p.uuid = ib.peer_uuid
			 ORDER BY p.name`,
		)
		.all<{ inbound_uuid: string; name: string; last_pulled_at: string | null; last_error: string | null }>();
	const peers = await Promise.all(
		(peerRows.results ?? []).map(async (peer) => {
			const pulled = (await db
				.prepare(
					`SELECT COUNT(*) AS n FROM events
					 WHERE source_peer_uuid = ?1
					   AND date >= date('now', '-1 day')`,
				)
				.bind(peer.inbound_uuid)
				.first<CountRow>())?.n ?? 0;
			return {
				name: peer.name,
				last_pulled_at: peer.last_pulled_at,
				last_error: peer.last_error,
				events_pulled_24h: pulled,
			};
		}),
	);

	// --- triage health --------------------------------------------------
	// pct of last-24h events with at least one tag attached. The 24h slice
	// is selected via idx_events_date so this stays bounded.
	const taggedSummary = await db
		.prepare(
			`SELECT
			   COUNT(*) AS total,
			   SUM(CASE WHEN EXISTS (
			       SELECT 1 FROM event_tags et WHERE et.event_uuid = e.uuid
			   ) THEN 1 ELSE 0 END) AS tagged
			 FROM events e
			 WHERE date >= date('now', '-1 day')`,
		)
		.first<{ total: number; tagged: number | null }>();
	const total24 = taggedSummary?.total ?? 0;
	const tagged24 = taggedSummary?.tagged ?? 0;
	const eventsWithTagsPct24h = total24 > 0 ? tagged24 / total24 : 0;

	// "Untagged > 15 minutes after ingest" — symptom of a backed-up triage
	// queue (queue depth itself isn't queryable from a Worker). We narrow
	// to the last-24h slice via the indexed `date` column FIRST so the
	// non-indexed `created_at < now-15m` predicate only scans a day's
	// worth of rows in the worst case.
	const untaggedOlderThan15m = (await db
		.prepare(
			`SELECT COUNT(*) AS n FROM events e
			 WHERE date >= date('now', '-1 day')
			   AND created_at < datetime('now', '-15 minutes')
			   AND NOT EXISTS (
			     SELECT 1 FROM event_tags et WHERE et.event_uuid = e.uuid
			   )`,
		)
		.first<CountRow>())?.n ?? 0;

	// --- cron -----------------------------------------------------------
	// Proxy: latest watermark advance across inbound peers. See file note.
	const cronLast = await db
		.prepare(`SELECT MAX(last_pulled_ts) AS last FROM inbound_peers`)
		.first<{ last: string | null }>();

	return c.json({
		orgs: { total: orgsTotal, active_last_7d: activeOrgs },
		events: { total: eventsTotal, last_24h: eventsLast24h },
		corroboration: { rows: corroborationRows, promoted: corroborationPromoted },
		destroylist: { by_sharing_group: destroylistBySharingGroup },
		peers,
		triage: {
			events_with_tags_pct_24h: Number(eventsWithTagsPct24h.toFixed(4)),
			untagged_older_than_15m: untaggedOlderThan15m,
		},
		cron: { last_run_at: cronLast?.last ?? null },
	});
});
