// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for the ACL migration surface (#241):
 *
 *   GET /api/v1/mailboxes — per-mailbox `acl_status: "scoped" | "unscoped"`
 *   POST /api/v1/mailboxes/:id/acl — lock-down endpoint (write ACL with
 *     caller as owner; 201 on first call, 200 idempotent; 403 without CF
 *     Access email).
 *
 * These tests build minimal inline Hono apps that mirror the relevant
 * routes from workers/index.ts, using the same in-memory R2 stub pattern
 * as the existing route tests. We do NOT import the full worker graph to
 * keep test execution fast and hermetic.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import {
	callerInAcl,
	readMailboxAcl,
	writeMailboxAcl,
} from "../../workers/lib/mailbox-acl";
import { requireMailbox, type MailboxContext } from "../../workers/lib/mailbox";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// ---------------------------------------------------------------------------
// Shared in-memory R2 stub
// ---------------------------------------------------------------------------

function makeR2Stub(initial: Record<string, string> = {}) {
	const store = { ...initial };
	return {
		async head(key: string) {
			return store[key] !== undefined ? { key } : null;
		},
		async get(key: string) {
			const val = store[key];
			if (!val) return null;
			return { json: async <T>() => JSON.parse(val) as T };
		},
		async put(key: string, value: string) {
			store[key] = value;
		},
		async delete(key: string) {
			delete store[key];
		},
		_store: store,
	};
}

// ---------------------------------------------------------------------------
// Helpers: list-mailboxes app (mirrors GET /api/v1/mailboxes from index.ts)
// ---------------------------------------------------------------------------

interface ListMailboxEntry {
	id: string;
	email: string;
	name: string;
	acl_status: "scoped" | "unscoped";
}

function makeListApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	type Env = { Bindings: { BUCKET: typeof bucket } };
	const app = new Hono<Env>();

	app.get("/api/v1/mailboxes", async (c) => {
		// List mailboxes by prefix-scanning R2 keys starting with "mailboxes/".
		// We reconstruct this inline from the store rather than importing
		// listMailboxes() to avoid pulling in the full worker-side email-helpers
		// dependency chain.
		const mailboxes = Object.keys((c.env.BUCKET as unknown as typeof bucket)._store)
			.filter((k) => k.startsWith("mailboxes/") && k.endsWith(".json") && !k.startsWith("mailboxes-acl/"))
			.map((k) => {
				const id = k.replace("mailboxes/", "").replace(".json", "");
				return { id, email: id, name: id };
			});

		const acls = await Promise.all(
			mailboxes.map((m) =>
				readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id),
			),
		);

		const effectiveCaller = callerEmail ?? null;
		if (!effectiveCaller) {
			return c.json(
				mailboxes.map((m, i) => ({
					...m,
					acl_status: acls[i] !== null ? "scoped" : "unscoped",
				})),
			);
		}

		const visible = mailboxes.filter((_, i) => callerInAcl(acls[i], effectiveCaller));
		const visibleAcls = acls.filter((_, i) => callerInAcl(acls[i], effectiveCaller));
		return c.json(
			visible.map((m, i) => ({
				...m,
				acl_status: visibleAcls[i] !== null ? "scoped" : "unscoped",
			})),
		);
	});

	return {
		fetch(path: string) {
			const hdrs: Record<string, string> = {};
			if (callerEmail) hdrs["cf-access-authenticated-user-email"] = callerEmail;
			return app.request(path, { headers: hdrs }, {
				BUCKET: bucket as unknown as R2Bucket,
			});
		},
		bucket,
	};
}

// ---------------------------------------------------------------------------
// Helpers: lock-down app (mirrors POST /api/v1/mailboxes/:id/acl + requireMailbox)
// ---------------------------------------------------------------------------

function makeLockDownApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = {
		idFromName: (_: string) => "fake-id",
		get: (_: unknown) => ({}),
	};

	const app = new Hono<MailboxContext>();
	app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);

	app.post("/api/v1/mailboxes/:mailboxId/acl", async (c) => {
		const mailboxId = c.req.param("mailboxId")!;
		const email = c.req.header("cf-access-authenticated-user-email");
		if (!email) {
			return c.json({ error: "CF Access identity required to lock down mailbox" }, 403);
		}
		const existing = await readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, mailboxId);
		if (existing !== null) {
			return c.json({ owner: existing.owner, members: existing.members, acl_status: "scoped" });
		}
		const owner = email.toLowerCase();
		const acl: MailboxAcl = { owner, members: [owner] };
		await writeMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, mailboxId, acl);
		return c.json({ owner: acl.owner, members: acl.members, acl_status: "scoped" }, 201);
	});

	return {
		fetch(path: string, options?: RequestInit) {
			const hdrs: Record<string, string> = {};
			if (callerEmail) hdrs["cf-access-authenticated-user-email"] = callerEmail;
			if (options?.headers) Object.assign(hdrs, options.headers as Record<string, string>);
			return app.request(
				path,
				{ ...options, headers: hdrs },
				{
					BUCKET: bucket as unknown as R2Bucket,
					MAILBOX: MAILBOX as unknown as DurableObjectNamespace,
				},
			);
		},
		bucket,
	};
}

// ---------------------------------------------------------------------------
// Tests: GET /api/v1/mailboxes — acl_status field (#241)
// ---------------------------------------------------------------------------

describe("GET /api/v1/mailboxes — acl_status field (#241)", () => {
	it("returns acl_status: 'unscoped' for a mailbox with no ACL blob", async () => {
		const { fetch } = makeListApp(
			{ "mailboxes/alice@example.com.json": "{}" },
			null,
		);
		const res = await fetch("/api/v1/mailboxes");
		expect(res.status).toBe(200);
		const body = (await res.json()) as ListMailboxEntry[];
		expect(body).toHaveLength(1);
		expect(body[0].id).toBe("alice@example.com");
		expect(body[0].acl_status).toBe("unscoped");
	});

	it("returns acl_status: 'scoped' for a mailbox with an ACL blob", async () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const { fetch } = makeListApp(
			{
				"mailboxes/alice@example.com.json": "{}",
				"mailboxes-acl/alice@example.com.json": JSON.stringify(acl),
			},
			null,
		);
		const res = await fetch("/api/v1/mailboxes");
		expect(res.status).toBe(200);
		const body = (await res.json()) as ListMailboxEntry[];
		expect(body[0].acl_status).toBe("scoped");
	});

	it("returns mixed scoped/unscoped when multiple mailboxes exist", async () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const { fetch } = makeListApp(
			{
				"mailboxes/alice@example.com.json": "{}",
				"mailboxes-acl/alice@example.com.json": JSON.stringify(acl),
				"mailboxes/bob@example.com.json": "{}",
				// bob has no ACL blob → unscoped
			},
			null,
		);
		const res = await fetch("/api/v1/mailboxes");
		expect(res.status).toBe(200);
		const body = (await res.json()) as ListMailboxEntry[];
		expect(body).toHaveLength(2);
		const alice = body.find((m) => m.id === "alice@example.com")!;
		const bob = body.find((m) => m.id === "bob@example.com")!;
		expect(alice.acl_status).toBe("scoped");
		expect(bob.acl_status).toBe("unscoped");
	});

	it("returns acl_status: 'scoped' for all mailboxes once all are locked down", async () => {
		const aliceAcl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const bobAcl: MailboxAcl = { owner: "bob@example.com", members: ["bob@example.com"] };
		const { fetch } = makeListApp(
			{
				"mailboxes/alice@example.com.json": "{}",
				"mailboxes-acl/alice@example.com.json": JSON.stringify(aliceAcl),
				"mailboxes/bob@example.com.json": "{}",
				"mailboxes-acl/bob@example.com.json": JSON.stringify(bobAcl),
			},
			null,
		);
		const res = await fetch("/api/v1/mailboxes");
		const body = (await res.json()) as ListMailboxEntry[];
		expect(body.every((m) => m.acl_status === "scoped")).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Tests: POST /api/v1/mailboxes/:id/acl — lock-down endpoint (#241)
// ---------------------------------------------------------------------------

describe("POST /api/v1/mailboxes/:id/acl — lock-down endpoint (#241)", () => {
	const mailboxId = "alice@example.com";
	const mailboxKey = `mailboxes/${mailboxId}.json`;
	const aclKey = `mailboxes-acl/${mailboxId}.json`;

	it("returns 403 when no CF Access email header is present", async () => {
		const { fetch } = makeLockDownApp({ [mailboxKey]: "{}" }, null);
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl`, { method: "POST" });
		expect(res.status).toBe(403);
	});

	it("writes ACL with caller as owner and returns 201 on first call", async () => {
		const { fetch, bucket } = makeLockDownApp({ [mailboxKey]: "{}" }, "alice@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl`, { method: "POST" });
		expect(res.status).toBe(201);
		const body = (await res.json()) as { owner: string; members: string[]; acl_status: string };
		expect(body.owner).toBe("alice@example.com");
		expect(body.members).toContain("alice@example.com");
		expect(body.acl_status).toBe("scoped");
		// Verify persisted to R2
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.owner).toBe("alice@example.com");
		expect(stored.members).toContain("alice@example.com");
	});

	it("is idempotent: returns 200 (not 201) when ACL already exists", async () => {
		const existingAcl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const { fetch, bucket } = makeLockDownApp(
			{
				[mailboxKey]: "{}",
				[aclKey]: JSON.stringify(existingAcl),
			},
			"alice@example.com",
		);
		const aclBefore = bucket._store[aclKey];
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl`, { method: "POST" });
		expect(res.status).toBe(200);
		const body = (await res.json()) as { acl_status: string };
		expect(body.acl_status).toBe("scoped");
		// ACL should not have been overwritten
		expect(bucket._store[aclKey]).toBe(aclBefore);
	});

	it("normalises the caller email to lower-case before writing", async () => {
		const { fetch, bucket } = makeLockDownApp({ [mailboxKey]: "{}" }, "ALICE@EXAMPLE.COM");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl`, { method: "POST" });
		expect(res.status).toBe(201);
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.owner).toBe("alice@example.com");
		expect(stored.members).toContain("alice@example.com");
		expect(stored.members).not.toContain("ALICE@EXAMPLE.COM");
	});

	it("returns 404 when the mailbox does not exist", async () => {
		const { fetch } = makeLockDownApp({}, "alice@example.com");
		// requireMailbox returns 404 when the mailbox settings blob is missing
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl`, { method: "POST" });
		expect(res.status).toBe(404);
	});

	it("after lock-down, GET /api/v1/mailboxes shows acl_status: 'scoped'", async () => {
		// Simulate the full flow: mailbox starts unscoped, lock-down writes ACL,
		// then list shows scoped. We verify this by using a shared store.
		const sharedStore: Record<string, string> = { [mailboxKey]: "{}" };

		// 1. Before lock-down: unscoped
		const { fetch: listFetch } = makeListApp({ ...sharedStore }, null);
		const before = (await (await listFetch("/api/v1/mailboxes")).json()) as ListMailboxEntry[];
		expect(before[0].acl_status).toBe("unscoped");

		// 2. Lock down
		const { fetch: lockFetch, bucket } = makeLockDownApp(sharedStore, "alice@example.com");
		const lockRes = await lockFetch(`/api/v1/mailboxes/${mailboxId}/acl`, { method: "POST" });
		expect(lockRes.status).toBe(201);

		// 3. After lock-down: scoped (use the same bucket._store)
		const { fetch: listFetch2 } = makeListApp({ ...sharedStore, ...bucket._store }, null);
		const after = (await (await listFetch2("/api/v1/mailboxes")).json()) as ListMailboxEntry[];
		expect(after[0].acl_status).toBe("scoped");
	});
});
