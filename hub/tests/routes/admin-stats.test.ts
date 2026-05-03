// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { adminStatsRoutes } from "../../src/routes/admin/stats";
import { makeTestDb, type TestDb } from "../helpers/d1";
import type { Env } from "../../src/types";

let db: TestDb;
let env: Env;

beforeEach(() => {
	db = makeTestDb();
	env = {
		DB: db.d1,
		AI: {} as Ai,
		TRIAGE_QUEUE: { send: async () => {} } as never,
		HUB_ADMIN_KEY: "admin-secret",
	} as Env;
});

afterEach(() => db.close());

function appReq(path: string, init?: RequestInit) {
	const app = new Hono<{ Bindings: Env }>();
	app.route("/admin", adminStatsRoutes);
	return app.request(`/admin${path}`, init, env as never);
}

const adminAuth = { Authorization: "admin-secret" };

describe("GET /admin/stats — auth", () => {
	it("returns 401 with no Authorization header", async () => {
		const res = await appReq("/stats");
		expect(res.status).toBe(401);
	});

	it("returns 401 with the wrong admin key", async () => {
		const res = await appReq("/stats", { headers: { Authorization: "nope" } });
		expect(res.status).toBe(401);
	});

	it("returns 401 when HUB_ADMIN_KEY is unset", async () => {
		(env as { HUB_ADMIN_KEY: string | undefined }).HUB_ADMIN_KEY = "" as string;
		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(401);
	});
});

describe("GET /admin/stats — shape on an empty hub", () => {
	it("returns the documented shape with all-zero counters", async () => {
		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as Record<string, unknown>;

		expect(body).toMatchObject({
			orgs: { total: 0, active_last_7d: 0 },
			events: { total: 0, last_24h: 0 },
			corroboration: { rows: 0, promoted: 0 },
			destroylist: { by_sharing_group: [] },
			peers: [],
			triage: { events_with_tags_pct_24h: 0, untagged_older_than_15m: 0 },
			cron: { last_run_at: null },
		});
	});
});

describe("GET /admin/stats — happy path with seeded fixtures", () => {
	it("aggregates orgs, events, corroboration, destroylist, peers, triage, cron", async () => {
		const today = new Date().toISOString().slice(0, 10);
		const eightDaysAgo = new Date(Date.now() - 8 * 86_400_000).toISOString().slice(0, 10);

		// Two orgs — one active, one stale.
		db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, ?)`).run("org-active", "Active", 1.0);
		db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, ?)`).run("org-stale", "Stale", 1.0);

		// Sharing groups.
		db.raw.prepare(`INSERT INTO sharing_groups (uuid, name) VALUES (?, ?)`).run("sg-pub", "public");
		db.raw.prepare(`INSERT INTO sharing_groups (uuid, name) VALUES (?, ?)`).run("sg-empty", "empty");

		// Events: 2 by active org today (one tagged, one not), 1 by stale org 8d ago.
		const insertEvent = db.raw.prepare(
			`INSERT INTO events (uuid, orgc_uuid, sharing_group_uuid, info, date, timestamp, event_json, created_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		);
		// "Old" enough that the 15-minute predicate fires for the untagged one.
		// Production rows use the SQLite default `datetime('now')` format
		// (`YYYY-MM-DD HH:MM:SS`, space separator, no `Z`), so seed in the
		// same format — ISO-8601 with `T` would lex-compare greater than
		// SQLite's `datetime('now','-15 minutes')` and break the predicate.
		const toSqlite = (d: Date) => d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
		const sixteenMinAgo = toSqlite(new Date(Date.now() - 16 * 60_000));
		const oneMinAgo = toSqlite(new Date(Date.now() - 60_000));
		insertEvent.run("ev-tagged", "org-active", "sg-pub", "tagged", today, today + "T00:00:00", "{}", sixteenMinAgo);
		insertEvent.run("ev-untagged-old", "org-active", "sg-pub", "stuck", today, today + "T00:00:00", "{}", sixteenMinAgo);
		insertEvent.run("ev-untagged-fresh", "org-active", "sg-pub", "fresh", today, today + "T00:00:00", "{}", oneMinAgo);
		insertEvent.run("ev-stale", "org-stale", "sg-pub", "stale", eightDaysAgo, eightDaysAgo + "T00:00:00", "{}", eightDaysAgo + "T00:00:00");

		// Tag exactly one event so the pct lands at 1/3.
		db.raw.prepare(`INSERT INTO tags (name) VALUES (?)`).run("phishing");
		db.raw.prepare(`INSERT INTO event_tags (event_uuid, tag_name) VALUES (?, ?)`).run("ev-tagged", "phishing");

		// Corroboration rows. Two promoted (sg-pub), one not promoted (sg-pub).
		const insertCorr = db.raw.prepare(
			`INSERT INTO corroboration (sharing_group_uuid, attribute_type, value, score, contributor_count)
			 VALUES (?, ?, ?, ?, ?)`,
		);
		insertCorr.run("sg-pub", "domain", "evil1.example", 3.0, 2);
		insertCorr.run("sg-pub", "domain", "evil2.example", 2.5, 3);
		insertCorr.run("sg-pub", "domain", "weak.example", 1.0, 1);
		insertCorr.run("sg-empty", "domain", "lonely.example", 0.5, 1);

		// Cron heartbeat row — what /admin/stats now reads for cron.last_run_at.
		// (Independent of the per-peer last_pulled_ts seeded below — that's
		// the property of this fix: a cron heartbeat that doesn't depend on
		// any peer succeeding.)
		const cronAt = Date.now() - 30_000;
		db.raw.prepare(`INSERT INTO cron_runs (name, last_run_at) VALUES (?, ?)`).run("inbound_sync", cronAt);

		// Inbound peer, last pulled ~now, plus one "pulled in last 24h" event.
		const lastPulled = new Date(Date.now() - 60_000).toISOString();
		db.raw.prepare(`INSERT INTO peers (uuid, name) VALUES (?, ?)`).run("peer-1", "CIRCL");
		db.raw.prepare(
			`INSERT INTO inbound_peers (uuid, peer_uuid, base_url, api_key_secret_name,
			   synthetic_org_uuid, default_sharing_group_uuid, last_pulled_ts, last_error)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		).run("ib-1", "peer-1", "https://misp.example", "K", "org-active", "sg-pub", lastPulled, null);
		// One event attributed to that peer in the 24h window.
		insertEvent.run("ev-from-peer", "org-active", "sg-pub", "from peer", today, today + "T00:00:00", "{}", oneMinAgo);
		db.raw.prepare(`UPDATE events SET source_peer_uuid = ? WHERE uuid = ?`).run("ib-1", "ev-from-peer");

		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as {
			orgs: { total: number; active_last_7d: number };
			events: { total: number; last_24h: number };
			corroboration: { rows: number; promoted: number };
			destroylist: { by_sharing_group: Array<{ uuid: string; name: string; size: number }> };
			peers: Array<{ name: string; last_pulled_at: string | null; last_error: string | null; events_pulled_24h: number }>;
			triage: { events_with_tags_pct_24h: number; untagged_older_than_15m: number };
			cron: { last_run_at: number | null };
		};

		expect(body.orgs.total).toBe(2);
		// Active = orgs with an event in last 7d. Only org-active qualifies.
		expect(body.orgs.active_last_7d).toBe(1);

		expect(body.events.total).toBe(5);
		expect(body.events.last_24h).toBe(4); // four events with `date` = today

		expect(body.corroboration.rows).toBe(4);
		// score>=2 AND contributors>=2 -> only the two sg-pub rows.
		expect(body.corroboration.promoted).toBe(2);

		// Destroylist sizes: sg-pub=2, sg-empty=0. Order is by sg.name asc.
		expect(body.destroylist.by_sharing_group).toEqual([
			{ uuid: "sg-empty", name: "empty", size: 0 },
			{ uuid: "sg-pub", name: "public", size: 2 },
		]);

		expect(body.peers).toHaveLength(1);
		expect(body.peers[0]).toMatchObject({
			name: "CIRCL",
			last_pulled_at: lastPulled,
			last_error: null,
			events_pulled_24h: 1,
		});

		// Triage: 1 of 4 today's events tagged -> 0.25.
		expect(body.triage.events_with_tags_pct_24h).toBeCloseTo(0.25, 4);
		// Untagged older than 15m: ev-untagged-old qualifies. ev-tagged is
		// excluded by the EXISTS, ev-untagged-fresh is too new, ev-from-peer
		// is too new, ev-stale is outside the 24h date window. So count = 1.
		expect(body.triage.untagged_older_than_15m).toBe(1);

		expect(body.cron.last_run_at).toBe(cronAt);
	});
});

describe("GET /admin/stats — cron.last_run_at", () => {
	it("returns null when cron_runs is empty (cron has never fired)", async () => {
		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as { cron: { last_run_at: number | null } };
		expect(body.cron.last_run_at).toBeNull();
	});

	it("returns the cron_runs row's epoch-ms timestamp when present", async () => {
		const stamped = 1_700_000_000_000;
		db.raw.prepare(`INSERT INTO cron_runs (name, last_run_at) VALUES (?, ?)`).run("inbound_sync", stamped);
		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as { cron: { last_run_at: number | null } };
		expect(body.cron.last_run_at).toBe(stamped);
	});

	it("ignores rows for other cron names", async () => {
		// Defensive: future crons may also stamp this table; /admin/stats
		// must return only the inbound_sync watermark.
		db.raw.prepare(`INSERT INTO cron_runs (name, last_run_at) VALUES (?, ?)`).run("some_other_cron", 1_800_000_000_000);
		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as { cron: { last_run_at: number | null } };
		expect(body.cron.last_run_at).toBeNull();
	});

	it("does NOT fall back to inbound_peers.last_pulled_ts when cron_runs is empty", async () => {
		// Regression guard for the bug this issue fixes: if every peer is
		// failing, the proxy advanced cron.last_run_at via a healthy peer's
		// watermark. With cron_runs as the source of truth, an empty table
		// returns null even if peers have pulled — the cron heartbeat is
		// independent of peer health.
		db.raw.prepare(`INSERT INTO peers (uuid, name) VALUES (?, ?)`).run("p", "P");
		db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, ?)`).run("o", "O", 1.0);
		db.raw.prepare(`INSERT INTO sharing_groups (uuid, name) VALUES (?, ?)`).run("sg", "sg");
		db.raw.prepare(
			`INSERT INTO inbound_peers (uuid, peer_uuid, base_url, api_key_secret_name,
			   synthetic_org_uuid, default_sharing_group_uuid, last_pulled_ts)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		).run("ib", "p", "https://x", "K", "o", "sg", new Date().toISOString());

		const res = await appReq("/stats", { headers: adminAuth });
		expect(res.status).toBe(200);
		const body = await res.json() as { cron: { last_run_at: number | null } };
		expect(body.cron.last_run_at).toBeNull();
	});
});
