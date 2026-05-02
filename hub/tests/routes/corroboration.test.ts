// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Hono } from "hono";
import { corroborationRoutes } from "../../src/routes/corroboration";
import { sha256 } from "../../src/lib/hash";
import { makeTestDb, type TestDb } from "../helpers/d1";
import type { Env } from "../../src/types";

let db: TestDb;
let env: Env;

const SELF_ORG = "11111111-1111-1111-1111-111111111111";
const OTHER_ORG = "22222222-2222-2222-2222-222222222222";
const THIRD_ORG = "33333333-3333-3333-3333-333333333333";
const SELF_KEY = "self-api-key";

beforeEach(async () => {
	db = makeTestDb();
	env = {
		DB: db.d1,
		AI: {} as Ai,
		TRIAGE_QUEUE: { send: async () => {} } as never,
		HUB_ADMIN_KEY: "admin-secret",
	} as Env;

	// Seed orgs and an api_key for SELF_ORG so requireOrg auth succeeds.
	db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, 1.0)`)
		.run(SELF_ORG, "self");
	db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, 1.0)`)
		.run(OTHER_ORG, "other");
	db.raw.prepare(`INSERT INTO orgs (uuid, name, trust) VALUES (?, ?, 1.0)`)
		.run(THIRD_ORG, "third");

	const keyHash = await sha256(SELF_KEY);
	db.raw
		.prepare(`INSERT INTO api_keys (key_hash, org_uuid, label) VALUES (?, ?, 'test')`)
		.run(keyHash, SELF_ORG);
});

afterEach(() => db.close());

function appReq(path: string, init?: RequestInit) {
	const app = new Hono<{ Bindings: Env }>();
	app.route("/api/v1/corroboration", corroborationRoutes);
	return app.request(path, init, env as never);
}

/**
 * Inserts a corroboration row + N contributors. `lastSeen` is an ISO-8601
 * timestamp (matches what `applyCorroboration` writes in production).
 */
function seedCorroboration(opts: {
	id: number;
	type: string;
	value: string;
	lastSeen: string;
	contributors: string[];
}) {
	db.raw
		.prepare(
			`INSERT INTO corroboration
			   (id, sharing_group_uuid, attribute_type, value, first_seen, last_seen, contributor_count, score)
			 VALUES (?, NULL, ?, ?, ?, ?, ?, ?)`,
		)
		.run(
			opts.id,
			opts.type,
			opts.value,
			opts.lastSeen,
			opts.lastSeen,
			opts.contributors.length,
			opts.contributors.length * 1.0,
		);
	for (const orgc of opts.contributors) {
		db.raw
			.prepare(
				`INSERT INTO corroboration_contributors (corroboration_id, orgc_uuid) VALUES (?, ?)`,
			)
			.run(opts.id, orgc);
	}
}

describe("GET /api/v1/corroboration", () => {
	it("rejects unauthenticated requests with 401", async () => {
		const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${SELF_ORG}&since=${encodeURIComponent(since)}`,
		);
		expect(res.status).toBe(401);
	});

	it("rejects missing query params with 400", async () => {
		const res = await appReq(`/api/v1/corroboration`, {
			headers: { Authorization: SELF_KEY },
		});
		expect(res.status).toBe(400);
	});

	it("rejects malformed `since` with 400", async () => {
		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${SELF_ORG}&since=not-a-date`,
			{ headers: { Authorization: SELF_KEY } },
		);
		expect(res.status).toBe(400);
	});

	it("rejects orgUuid that doesn't match the authenticated org with 403", async () => {
		const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${OTHER_ORG}&since=${encodeURIComponent(since)}`,
			{ headers: { Authorization: SELF_KEY } },
		);
		expect(res.status).toBe(403);
	});

	it("counts an attribute corroborated by self + another org in window", async () => {
		const inWindow = new Date(Date.now() - 60 * 60 * 1000).toISOString();
		const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

		seedCorroboration({
			id: 1,
			type: "domain",
			value: "evil.example",
			lastSeen: inWindow,
			contributors: [SELF_ORG, OTHER_ORG],
		});

		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${SELF_ORG}&since=${encodeURIComponent(since)}`,
			{ headers: { Authorization: SELF_KEY } },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { corroboratedCount: number };
		expect(body.corroboratedCount).toBe(1);
	});

	it("does not count when only self is the contributor (no second contributor)", async () => {
		const inWindow = new Date(Date.now() - 60 * 60 * 1000).toISOString();
		const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

		// Same contributor twice would be deduped by the contributors PK in
		// production — model the post-dedup state: a single contributor.
		seedCorroboration({
			id: 1,
			type: "domain",
			value: "lonely.example",
			lastSeen: inWindow,
			contributors: [SELF_ORG],
		});

		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${SELF_ORG}&since=${encodeURIComponent(since)}`,
			{ headers: { Authorization: SELF_KEY } },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { corroboratedCount: number };
		expect(body.corroboratedCount).toBe(0);
	});

	it("does not count attributes whose `last_seen` falls outside the window", async () => {
		const outOfWindow = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
		const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

		seedCorroboration({
			id: 1,
			type: "domain",
			value: "stale.example",
			lastSeen: outOfWindow,
			contributors: [SELF_ORG, OTHER_ORG],
		});

		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${SELF_ORG}&since=${encodeURIComponent(since)}`,
			{ headers: { Authorization: SELF_KEY } },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { corroboratedCount: number };
		expect(body.corroboratedCount).toBe(0);
	});

	it("counts each corroborated attribute once even with three contributors", async () => {
		const inWindow = new Date(Date.now() - 60 * 60 * 1000).toISOString();
		const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

		seedCorroboration({
			id: 1,
			type: "url",
			value: "https://a.example",
			lastSeen: inWindow,
			contributors: [SELF_ORG, OTHER_ORG, THIRD_ORG],
		});
		seedCorroboration({
			id: 2,
			type: "url",
			value: "https://b.example",
			lastSeen: inWindow,
			contributors: [SELF_ORG, OTHER_ORG],
		});
		// Row not contributed by self — must not count.
		seedCorroboration({
			id: 3,
			type: "url",
			value: "https://c.example",
			lastSeen: inWindow,
			contributors: [OTHER_ORG, THIRD_ORG],
		});

		const res = await appReq(
			`/api/v1/corroboration?orgUuid=${SELF_ORG}&since=${encodeURIComponent(since)}`,
			{ headers: { Authorization: SELF_KEY } },
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { corroboratedCount: number };
		expect(body.corroboratedCount).toBe(2);
	});
});
