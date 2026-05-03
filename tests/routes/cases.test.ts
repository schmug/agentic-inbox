// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for `workers/routes/cases.ts` covering the per-case
 * verdict score plumbing added in issue #126:
 *
 *   1. POST /report-phish copies the originating email's
 *      `security_score` onto the case record via `createCase`.
 *   2. GET /:caseId surfaces the persisted `score` in the API response.
 *
 * The mailbox DO stub is hand-rolled here — these tests don't need real
 * DO storage, only that the score field flows through `createCase`'s
 * input and back out of `getCase`'s output. The schema-level test
 * (column exists, nullable) lives implicitly in this round-trip:
 * `score: null` and `score: 78` both pass through unchanged.
 */

import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { describe, expect, it, vi } from "vitest";

// Module mock: replace requireMailbox with a no-op so our parent
// middleware can inject the fake stub before caseRoutes runs. Without
// this, the real middleware would call `env.BUCKET.head()` and
// `env.MAILBOX.get()` which we don't have stubs for in the unit-test
// pool.
vi.mock("../../workers/lib/mailbox", async (orig) => {
	const original = await orig<typeof import("../../workers/lib/mailbox")>();
	return {
		...original,
		requireMailbox: createMiddleware(async (_c, next) => {
			await next();
		}),
	};
});

import { caseRoutes } from "../../workers/routes/cases";
import type { MailboxContext } from "../../workers/lib/mailbox";

interface FakeCaseRow {
	id: string;
	created_at: string;
	updated_at: string;
	status: string;
	title: string;
	notes: string | null;
	shared_to_hub: number;
	hub_event_uuid: string | null;
	score: number | null;
	emails: Array<{ case_id: string; email_id: string }>;
	observables: Array<{ id: string; case_id: string; kind: string; value: string }>;
}

interface FakeEmailRow {
	id: string;
	subject: string | null;
	sender: string;
	body: string | null;
	date: string;
	security_score: number | null;
}

function makeStub(emails: Record<string, FakeEmailRow>) {
	const cases = new Map<string, FakeCaseRow>();
	const createCalls: Array<{
		title: string;
		notes?: string;
		emailId?: string;
		score?: number | null;
	}> = [];

	const stub = {
		async getEmail(id: string) {
			return emails[id] ?? null;
		},
		async createCase(input: {
			title: string;
			notes?: string;
			emailId?: string;
			observables?: Array<{ kind: string; value: string }>;
			score?: number | null;
		}) {
			createCalls.push({
				title: input.title,
				notes: input.notes,
				emailId: input.emailId,
				score: input.score,
			});
			const id = `case_${cases.size + 1}`;
			const now = "2026-05-03T00:00:00Z";
			const row: FakeCaseRow = {
				id,
				created_at: now,
				updated_at: now,
				status: "open",
				title: input.title.slice(0, 500),
				notes: input.notes ?? null,
				shared_to_hub: 0,
				hub_event_uuid: null,
				score: input.score ?? null,
				emails: input.emailId
					? [{ case_id: id, email_id: input.emailId }]
					: [],
				observables: (input.observables ?? []).map((o, i) => ({
					id: `obs_${i}`,
					case_id: id,
					kind: o.kind,
					value: o.value,
				})),
			};
			cases.set(id, row);
			return { id };
		},
		async getCase(id: string) {
			return cases.get(id) ?? null;
		},
		async updateCase() { /* no-op for these tests */ },
		async flagSender() { /* no-op */ },
	};

	return { stub, cases, createCalls };
}

function makeApp(stub: ReturnType<typeof makeStub>["stub"]) {
	// Mount caseRoutes under the same prefix the real app uses so the
	// `:mailboxId` path param is set when requireMailbox runs.
	// caseRoutes.use("*", requireMailbox) runs against R2 — for these
	// tests we need to short-circuit that, so we wrap caseRoutes in a
	// thin parent app that injects the fake stub before the route's own
	// middleware fires.
	const app = new Hono<MailboxContext>();
	app.use("*", async (c, next) => {
		c.set("mailboxStub", stub as unknown as DurableObjectStub<never>);
		await next();
	});
	app.route("/api/v1/mailboxes/:mailboxId/cases", caseRoutes);
	return app;
}

// Minimal env stub.
//   - BUCKET.head() must return truthy so requireMailbox doesn't 404.
//   - BUCKET.get() returns null so the optional hub-config lookup
//     inside report-phish short-circuits at "not configured".
//   - MAILBOX is unused because we override `c.var.mailboxStub` before
//     requireMailbox tries to instantiate a DO stub.
const fakeEnv = {
	BUCKET: {
		async get() { return null; },
		async head() {
			return { key: "mailboxes/m1.json" };
		},
		async put() { /* no-op */ },
	},
	MAILBOX: {
		idFromName() { return {}; },
		get() { return {}; },
	},
} as unknown as Parameters<Hono["request"]>[2];

describe("workers/routes/cases — issue #126 per-case score", () => {
	it("report-phish: copies the email's security_score onto the case row", async () => {
		const { stub, createCalls, cases } = makeStub({
			"em_1": {
				id: "em_1",
				subject: "URGENT: wire transfer",
				sender: "ceo@evil.example",
				body: "<p>Click https://phish.example/login</p>",
				date: "2026-05-01T00:00:00Z",
				security_score: 78,
			},
		});
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/cases/report-phish",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ emailId: "em_1" }),
			},
			fakeEnv,
		);
		expect(res.status).toBe(201);
		const body = (await res.json()) as { caseId: string };
		expect(body.caseId).toBeTruthy();

		// createCase was called once, with the email's score plumbed through.
		expect(createCalls).toHaveLength(1);
		expect(createCalls[0].score).toBe(78);

		// Persisted on the row.
		expect(cases.get(body.caseId)?.score).toBe(78);
	});

	it("report-phish: persists score=null when the originating email has no security_score", async () => {
		const { stub, createCalls, cases } = makeStub({
			"em_unscored": {
				id: "em_unscored",
				subject: "newsletter",
				sender: "list@example.com",
				body: "hi",
				date: "2026-05-01T00:00:00Z",
				security_score: null,
			},
		});
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/cases/report-phish",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ emailId: "em_unscored" }),
			},
			fakeEnv,
		);
		expect(res.status).toBe(201);
		const body = (await res.json()) as { caseId: string };

		expect(createCalls[0].score).toBeNull();
		expect(cases.get(body.caseId)?.score).toBeNull();
	});

	it("GET /:caseId returns `score` in the response shape", async () => {
		const { stub } = makeStub({});
		// Seed a case directly through createCase so the row exists.
		await stub.createCase({
			title: "manual case",
			emailId: undefined,
			observables: [],
			score: 42,
		});
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/cases/case_1",
			undefined,
			fakeEnv,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			case: { id: string; score: number | null };
		};
		expect(body.case.id).toBe("case_1");
		expect(body.case.score).toBe(42);
	});

	it("GET /:caseId returns score: null when the case was created without one", async () => {
		const { stub } = makeStub({});
		await stub.createCase({
			title: "manual case no score",
			emailId: undefined,
			observables: [],
			// score omitted → createCase normalizes to null
		});
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/cases/case_1",
			undefined,
			fakeEnv,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			case: { score: number | null };
		};
		expect(body.case.score).toBeNull();
	});

	it("POST /cases accepts an explicit score in the request body", async () => {
		const { stub, createCalls } = makeStub({});
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/cases",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					title: "explicit-score case",
					score: 55,
				}),
			},
			fakeEnv,
		);
		expect(res.status).toBe(201);
		expect(createCalls).toHaveLength(1);
		expect(createCalls[0].score).toBe(55);
	});

	it("POST /cases rejects out-of-range scores", async () => {
		const { stub, createCalls } = makeStub({});
		const app = makeApp(stub);

		const res = await app.request(
			"/api/v1/mailboxes/m1/cases",
			{
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({
					title: "bad-score case",
					score: 150, // outside 0..100
				}),
			},
			fakeEnv,
		);
		expect(res.status).toBe(400);
		expect(createCalls).toHaveLength(0);
	});
});

