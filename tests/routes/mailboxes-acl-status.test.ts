// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for issue #241: acl_status field on GET /api/v1/mailboxes and
 * the POST /api/v1/mailboxes/:id/acl lock-down endpoint.
 *
 * Uses in-memory R2 stubs and minimal Hono apps — same pattern as
 * tests/routes/acl-members.test.ts.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireMailbox, type MailboxContext } from "../../workers/lib/mailbox";
import { aclMemberRoutes } from "../../workers/routes/acl-members";
import { readMailboxAcl, callerInAcl } from "../../workers/lib/mailbox-acl";
import { listMailboxes } from "../../workers/lib/email-helpers";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// ---------------------------------------------------------------------------
// In-memory R2 stub (supports head / get / put / delete / list)
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
		async list({ prefix }: { prefix: string }) {
			const objects = Object.keys(store)
				.filter((k) => k.startsWith(prefix))
				.map((key) => ({ key }));
			return { objects };
		},
		_store: store,
	};
}

// ---------------------------------------------------------------------------
// Minimal list-endpoint app (replicates GET /api/v1/mailboxes from index.ts)
// ---------------------------------------------------------------------------

function makeListApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = { idFromName: () => "fake-id", get: () => ({}) };

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket; MAILBOX: typeof MAILBOX } }>();

	app.get("/api/v1/mailboxes", async (c) => {
		const caller = callerEmail;
		const allMailboxes = await listMailboxes(c.env.BUCKET as unknown as R2Bucket);
		const acls = await Promise.all(
			allMailboxes.map((m) => readMailboxAcl(c.env as unknown as { BUCKET: R2Bucket }, m.id)),
		);

		if (!caller) {
			return c.json(
				allMailboxes.map((m, i) => ({
					...m,
					name: m.id,
					acl_status: acls[i] ? "scoped" : "unscoped",
				})),
			);
		}

		const visible = allMailboxes
			.map((m, i) => ({ mailbox: m, acl: acls[i] }))
			.filter(({ acl }) => callerInAcl(acl, caller));

		return c.json(
			visible.map(({ mailbox, acl }) => ({
				...mailbox,
				name: mailbox.id,
				acl_status: acl ? "scoped" : "unscoped",
			})),
		);
	});

	return {
		fetch() {
			return app.request(
				"/api/v1/mailboxes",
				{},
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
// Lock-down endpoint app
// ---------------------------------------------------------------------------

function makeLockDownApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = { idFromName: () => "fake-id", get: () => ({}) };

	const app = new Hono<MailboxContext>();
	app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);
	app.route("/api/v1/mailboxes/:mailboxId/acl", aclMemberRoutes);

	return {
		post(mailboxId: string) {
			const hdrs: Record<string, string> = {};
			if (callerEmail) hdrs["cf-access-authenticated-user-email"] = callerEmail;
			return app.request(
				`/api/v1/mailboxes/${mailboxId}/acl`,
				{ method: "POST", headers: hdrs },
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
// Fixtures
// ---------------------------------------------------------------------------

const mailboxId = "alice@example.com";
const mailboxKey = `mailboxes/${mailboxId}.json`;
const aclKey = `mailboxes-acl/${mailboxId}.json`;

const scopedAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com"],
};

// ---------------------------------------------------------------------------
// acl_status on GET /api/v1/mailboxes
// ---------------------------------------------------------------------------

describe("GET /api/v1/mailboxes — acl_status field", () => {
	it("returns acl_status: unscoped for a mailbox with no ACL blob", async () => {
		const { fetch } = makeListApp({ [mailboxKey]: "{}" }, null);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string; acl_status: string }>;
		const mailbox = body.find((m) => m.id === mailboxId);
		expect(mailbox).toBeDefined();
		expect(mailbox?.acl_status).toBe("unscoped");
	});

	it("returns acl_status: scoped for a mailbox that has an ACL blob", async () => {
		const { fetch } = makeListApp(
			{ [mailboxKey]: "{}", [aclKey]: JSON.stringify(scopedAcl) },
			null,
		);
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string; acl_status: string }>;
		const mailbox = body.find((m) => m.id === mailboxId);
		expect(mailbox?.acl_status).toBe("scoped");
	});

	it("includes acl_status when callerEmail is set and filters by ACL", async () => {
		const secondId = "bob@example.com";
		const secondKey = `mailboxes/${secondId}.json`;
		const secondAclKey = `mailboxes-acl/${secondId}.json`;
		// alice has an ACL (visible to alice); bob has no ACL (visible to everyone)
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(scopedAcl),
			[secondKey]: "{}",
			// no ACL for bob's mailbox → unscoped, visible to anyone
		};
		const { fetch } = makeListApp(store, "alice@example.com");
		const res = await fetch();
		expect(res.status).toBe(200);
		const body = await res.json() as Array<{ id: string; acl_status: string }>;
		const aliceMailbox = body.find((m) => m.id === mailboxId);
		const bobMailbox = body.find((m) => m.id === secondId);
		expect(aliceMailbox?.acl_status).toBe("scoped");
		expect(bobMailbox?.acl_status).toBe("unscoped");

		// suppress unused import warning
		void secondAclKey;
	});
});

// ---------------------------------------------------------------------------
// POST /api/v1/mailboxes/:id/acl — lock-down endpoint
// ---------------------------------------------------------------------------

describe("POST /api/v1/mailboxes/:id/acl — lock down", () => {
	it("returns 201 and persists ACL with caller as owner for an unscoped mailbox", async () => {
		const { post, bucket } = makeLockDownApp({ [mailboxKey]: "{}" }, "alice@example.com");
		const res = await post(mailboxId);
		expect(res.status).toBe(201);
		const body = await res.json() as MailboxAcl;
		expect(body.owner).toBe("alice@example.com");
		expect(body.members).toContain("alice@example.com");
		// ACL was actually written to the stub
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.owner).toBe("alice@example.com");
		expect(stored.members).toContain("alice@example.com");
	});

	it("returns 409 when the mailbox already has an ACL", async () => {
		const store = { [mailboxKey]: "{}", [aclKey]: JSON.stringify(scopedAcl) };
		const { post } = makeLockDownApp(store, "alice@example.com");
		const res = await post(mailboxId);
		expect(res.status).toBe(409);
		const body = await res.json() as { error: string };
		expect(body.error).toBeTruthy();
	});

	it("returns 400 when no CF Access email is present (dev mode)", async () => {
		const { post } = makeLockDownApp({ [mailboxKey]: "{}" }, null);
		const res = await post(mailboxId);
		expect(res.status).toBe(400);
	});

	it("returns 404 when the mailbox does not exist", async () => {
		const { post } = makeLockDownApp({}, "alice@example.com");
		const res = await post(mailboxId);
		expect(res.status).toBe(404);
	});

	it("normalises caller email to lower-case in the persisted ACL", async () => {
		const { post, bucket } = makeLockDownApp({ [mailboxKey]: "{}" }, "ALICE@EXAMPLE.COM");
		const res = await post(mailboxId);
		expect(res.status).toBe(201);
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.owner).toBe("alice@example.com");
		expect(stored.members).toContain("alice@example.com");
	});

	it("subsequent GET /api/v1/mailboxes shows acl_status: scoped after lock-down", async () => {
		// Start unscoped
		const store: Record<string, string> = { [mailboxKey]: "{}" };
		const lockDown = makeLockDownApp(store, "alice@example.com");

		// Lock it down
		const lockRes = await lockDown.post(mailboxId);
		expect(lockRes.status).toBe(201);

		// Now query the list — the shared store now has the ACL blob
		const { fetch } = makeListApp(lockDown.bucket._store, "alice@example.com");
		const listRes = await fetch();
		expect(listRes.status).toBe(200);
		const body = await listRes.json() as Array<{ id: string; acl_status: string }>;
		const mailbox = body.find((m) => m.id === mailboxId);
		expect(mailbox?.acl_status).toBe("scoped");
	});
});
