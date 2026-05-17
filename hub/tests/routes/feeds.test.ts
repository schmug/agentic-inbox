// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { feedRoutes, publicFeedRoutes } from "../../src/routes/feeds";
import { applyCorroboration } from "../../src/lib/aggregate";
import { sha256 } from "../../src/lib/hash";
import { makeTestDb, type TestDb } from "../helpers/d1";
import type { Env } from "../../src/types";

let db: TestDb;
let env: Env;

const ORG_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const ORG_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const KEY_A = "api-key-A";
const KEY_B = "api-key-B";
const SG_1 = "sg-1";

async function seed() {
	db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, 'A', 1.0)`).run(ORG_A);
	db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, 'B', 1.0)`).run(ORG_B);
	db.raw.prepare(`INSERT INTO sharing_groups (uuid, name) VALUES (?, 'g1')`).run(SG_1);
	for (const o of [ORG_A, ORG_B]) {
		db.raw
			.prepare(`INSERT INTO sharing_group_orgs (sharing_group_uuid, org_uuid) VALUES (?, ?)`)
			.run(SG_1, o);
	}
	const hashA = await sha256(KEY_A);
	const hashB = await sha256(KEY_B);
	db.raw.prepare(`INSERT INTO api_keys (key_hash, org_uuid, label) VALUES (?, ?, 'A')`).run(hashA, ORG_A);
	db.raw.prepare(`INSERT INTO api_keys (key_hash, org_uuid, label) VALUES (?, ?, 'B')`).run(hashB, ORG_B);
}

beforeEach(async () => {
	db = makeTestDb();
	env = {
		DB: db.d1,
		AI: {} as Ai,
		TRIAGE_QUEUE: { send: async () => {} } as never,
		HUB_ADMIN_KEY: "admin-secret",
	} as Env;
	await seed();
});

afterEach(() => db.close());

function get(path: string, key: string) {
	const app = new Hono<{ Bindings: Env }>();
	app.route("/feeds", feedRoutes);
	return app.request(path, { headers: { Authorization: `Bearer ${key}` } }, env as never);
}

function getPublic(path: string) {
	const app = new Hono<{ Bindings: Env }>();
	app.route("/", publicFeedRoutes);
	return app.request(path, {}, env as never);
}

describe("GET /feeds/destroylist.txt own-org echo", () => {
	it("echoes caller's own single-contributor entries on their own pull", async () => {
		await applyCorroboration(db.d1, {
			event_uuid: "e1", orgc_uuid: ORG_A, sharing_group_uuid: SG_1,
			attributes: [{ type: "url", value: "https://only-A.example" }],
		});

		const res = await get(`/feeds/destroylist.txt?sharing_group=${SG_1}`, KEY_A);
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain("https://only-A.example");
	});

	it("does NOT leak org B's solo entries to org A's pull", async () => {
		await applyCorroboration(db.d1, {
			event_uuid: "e1", orgc_uuid: ORG_B, sharing_group_uuid: SG_1,
			attributes: [{ type: "url", value: "https://only-B.example" }],
		});

		const res = await get(`/feeds/destroylist.txt?sharing_group=${SG_1}`, KEY_A);
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).not.toContain("https://only-B.example");

		// And conversely org B sees their own.
		const resB = await get(`/feeds/destroylist.txt?sharing_group=${SG_1}`, KEY_B);
		expect(resB.status).toBe(200);
		expect(await resB.text()).toContain("https://only-B.example");
	});

	it("de-dupes entries that meet both the cross-org threshold and the own-org branch", async () => {
		for (const o of [ORG_A, ORG_B]) {
			await applyCorroboration(db.d1, {
				event_uuid: `e-${o}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [{ type: "url", value: "https://both.example" }],
			});
		}

		const res = await get(`/feeds/destroylist.txt?sharing_group=${SG_1}`, KEY_A);
		const body = await res.text();
		const occurrences = body.split("\n").filter((l) => l === "https://both.example").length;
		expect(occurrences).toBe(1);
	});
});

describe("GET /feeds/destroylist.txt corroboration counts (issue #23)", () => {
	it("emits score and contributor count comment before each value", async () => {
		for (const [i, o] of [ORG_A, ORG_B].entries()) {
			await applyCorroboration(db.d1, {
				event_uuid: `e${i}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [{ type: "url", value: "https://evil.example" }],
			});
		}

		const res = await get(`/feeds/destroylist.txt?sharing_group=${SG_1}`, KEY_A);
		const body = await res.text();
		// The comment line precedes the value line.
		const lines = body.split("\n");
		const valueIdx = lines.indexOf("https://evil.example");
		expect(valueIdx).toBeGreaterThan(0);
		const commentLine = lines[valueIdx - 1];
		expect(commentLine).toMatch(/^# score=\d+\.\d+ contributors=\d+$/);
		expect(commentLine).toContain("contributors=2");
	});

	it("parsers that skip # lines still get clean values from authenticated feed", async () => {
		for (const [i, o] of [ORG_A, ORG_B].entries()) {
			await applyCorroboration(db.d1, {
				event_uuid: `ep${i}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [{ type: "url", value: "https://parseable.example" }],
			});
		}

		const res = await get(`/feeds/destroylist.txt?sharing_group=${SG_1}`, KEY_A);
		const body = await res.text();
		const nonComment = body.split("\n").filter((l) => l && !l.startsWith("#"));
		expect(nonComment).toContain("https://parseable.example");
		// Every non-comment line is a plain value — no metadata leaks into values.
		for (const line of nonComment) {
			expect(line).not.toMatch(/score=/);
		}
	});
});

describe("GET /feeds/public/destroylist.txt (issue #23)", () => {
	it("returns 200 with empty body when no public sharing groups exist", async () => {
		const res = await getPublic("/destroylist.txt");
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain("# no public sharing groups configured");
	});

	it("does not require authentication", async () => {
		// No Authorization header — should not 401.
		const res = await getPublic("/destroylist.txt");
		expect(res.status).toBe(200);
	});

	it("exposes promoted entries from is_public=1 sharing groups", async () => {
		// Mark SG_1 as public.
		db.raw.prepare(`UPDATE sharing_groups SET is_public = 1 WHERE uuid = ?`).run(SG_1);

		// Two contributors → meets promotion threshold.
		for (const [i, o] of [ORG_A, ORG_B].entries()) {
			await applyCorroboration(db.d1, {
				event_uuid: `pub${i}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [{ type: "url", value: "https://public-evil.example" }],
			});
		}

		const res = await getPublic("/destroylist.txt");
		expect(res.status).toBe(200);
		const body = await res.text();
		expect(body).toContain("https://public-evil.example");
	});

	it("does NOT expose entries below the promotion threshold", async () => {
		db.raw.prepare(`UPDATE sharing_groups SET is_public = 1 WHERE uuid = ?`).run(SG_1);

		// Only one contributor — below the PROMOTION_CONTRIBUTORS = 2 threshold.
		await applyCorroboration(db.d1, {
			event_uuid: "single", orgc_uuid: ORG_A, sharing_group_uuid: SG_1,
			attributes: [{ type: "url", value: "https://single-contributor.example" }],
		});

		const res = await getPublic("/destroylist.txt");
		const body = await res.text();
		expect(body).not.toContain("https://single-contributor.example");
	});

	it("does NOT expose entries from non-public sharing groups", async () => {
		// SG_1 stays is_public=0 (default).
		for (const [i, o] of [ORG_A, ORG_B].entries()) {
			await applyCorroboration(db.d1, {
				event_uuid: `priv${i}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [{ type: "url", value: "https://private-only.example" }],
			});
		}

		const res = await getPublic("/destroylist.txt");
		const body = await res.text();
		expect(body).not.toContain("https://private-only.example");
	});

	it("includes corroboration count comments before each value", async () => {
		db.raw.prepare(`UPDATE sharing_groups SET is_public = 1 WHERE uuid = ?`).run(SG_1);

		for (const [i, o] of [ORG_A, ORG_B].entries()) {
			await applyCorroboration(db.d1, {
				event_uuid: `cnt${i}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [{ type: "url", value: "https://counted.example" }],
			});
		}

		const res = await getPublic("/destroylist.txt");
		const body = await res.text();
		const lines = body.split("\n");
		const valueIdx = lines.indexOf("https://counted.example");
		expect(valueIdx).toBeGreaterThan(0);
		const commentLine = lines[valueIdx - 1];
		expect(commentLine).toMatch(/^# score=\d+\.\d+ contributors=\d+$/);
		expect(commentLine).toContain("contributors=2");
	});

	it("de-dupes entries promoted by multiple public sharing groups", async () => {
		const SG_2 = "sg-2";
		db.raw.prepare(`INSERT INTO sharing_groups (uuid, name, is_public) VALUES (?, 'g2', 1)`).run(SG_2);
		db.raw.prepare(`UPDATE sharing_groups SET is_public = 1 WHERE uuid = ?`).run(SG_1);

		for (const sg of [SG_1, SG_2]) {
			for (const [i, o] of [ORG_A, ORG_B].entries()) {
				await applyCorroboration(db.d1, {
					event_uuid: `dup-${sg}-${i}`, orgc_uuid: o, sharing_group_uuid: sg,
					attributes: [{ type: "url", value: "https://dedup.example" }],
				});
			}
		}

		const res = await getPublic("/destroylist.txt");
		const body = await res.text();
		const occurrences = body.split("\n").filter((l) => l === "https://dedup.example").length;
		expect(occurrences).toBe(1);
	});

	it("filters by kinds query parameter", async () => {
		db.raw.prepare(`UPDATE sharing_groups SET is_public = 1 WHERE uuid = ?`).run(SG_1);

		for (const [i, o] of [ORG_A, ORG_B].entries()) {
			await applyCorroboration(db.d1, {
				event_uuid: `knd${i}`, orgc_uuid: o, sharing_group_uuid: SG_1,
				attributes: [
					{ type: "url", value: "https://url-kind.example" },
					{ type: "domain", value: "domain-kind.example" },
				],
			});
		}

		const res = await getPublic("/destroylist.txt?kinds=domain");
		const body = await res.text();
		expect(body).toContain("domain-kind.example");
		expect(body).not.toContain("https://url-kind.example");
	});
});
