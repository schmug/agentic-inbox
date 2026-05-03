// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { feedRoutes } from "../../src/routes/feeds";
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
