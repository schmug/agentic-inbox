// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Route-level tests for `workers/routes/acl-members.ts` (#240).
 *
 * Covers all acceptance cases using an in-memory R2 stub (same pattern as
 * `tests/lib/mailbox-acl.test.ts`). `requireMailbox` is NOT mocked — the
 * inline app wires it up with a real bucket stub so both the middleware ACL
 * check and the route-level owner check are exercised end-to-end.
 */

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireMailbox, type MailboxContext } from "../../workers/lib/mailbox";
import { aclMemberRoutes } from "../../workers/routes/acl-members";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";

// ---------------------------------------------------------------------------
// Shared in-memory R2 stub (mirrors makeFullR2Stub from mailbox-acl.test.ts)
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
// Test app factory
// ---------------------------------------------------------------------------

function makeApp(bucketStore: Record<string, string>, callerEmail: string | null) {
	const bucket = makeR2Stub(bucketStore);
	const MAILBOX = {
		idFromName: (_: string) => "fake-id",
		get: (_: unknown) => ({}),
	};

	const app = new Hono<MailboxContext>();
	// Wire the same middleware chain the production app uses.
	app.use("/api/v1/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);
	app.route("/api/v1/mailboxes/:mailboxId/acl", aclMemberRoutes);

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
// Shared fixtures
// ---------------------------------------------------------------------------

const mailboxId = "alice@example.com";
const mailboxKey = `mailboxes/${mailboxId}.json`;
const aclKey = `mailboxes-acl/${mailboxId}.json`;

function storeWithAcl(acl: MailboxAcl): Record<string, string> {
	return {
		[mailboxKey]: "{}",
		[aclKey]: JSON.stringify(acl),
	};
}

const aliceOnlyAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com"],
};

const aliceAndBobAcl: MailboxAcl = {
	owner: "alice@example.com",
	members: ["alice@example.com", "bob@example.com"],
};

// ---------------------------------------------------------------------------
// POST /api/v1/mailboxes/:mailboxId/acl/members
// ---------------------------------------------------------------------------

describe("POST /acl/members — add member", () => {
	it("owner adds a new member → 200 with updated ACL", async () => {
		const { fetch, bucket } = makeApp(storeWithAcl(aliceOnlyAcl), "alice@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl/members`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "bob@example.com" }),
		});
		expect(res.status).toBe(200);
		const body = await res.json() as MailboxAcl;
		expect(body.owner).toBe("alice@example.com");
		expect(body.members).toContain("bob@example.com");
		// Persisted to R2
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.members).toContain("bob@example.com");
	});

	it("idempotent: POST with already-present email → 200, no duplicate in members", async () => {
		const { fetch, bucket } = makeApp(storeWithAcl(aliceAndBobAcl), "alice@example.com");
		const before = bucket._store[aclKey];
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl/members`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "bob@example.com" }),
		});
		expect(res.status).toBe(200);
		const body = await res.json() as MailboxAcl;
		const bobCount = body.members.filter((m) => m === "bob@example.com").length;
		expect(bobCount).toBe(1);
		// R2 was not written (no change)
		expect(bucket._store[aclKey]).toBe(before);
	});

	it("non-owner admitted caller → 403", async () => {
		// Bob is in members (requireMailbox passes) but is not the owner.
		const { fetch } = makeApp(storeWithAcl(aliceAndBobAcl), "bob@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl/members`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "carol@example.com" }),
		});
		expect(res.status).toBe(403);
	});

	it("email input is normalised to lower-case before writing", async () => {
		const { fetch, bucket } = makeApp(storeWithAcl(aliceOnlyAcl), "alice@example.com");
		const res = await fetch(`/api/v1/mailboxes/${mailboxId}/acl/members`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ email: "BOB@EXAMPLE.COM" }),
		});
		expect(res.status).toBe(200);
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.members).toContain("bob@example.com");
		expect(stored.members).not.toContain("BOB@EXAMPLE.COM");
	});
});

// ---------------------------------------------------------------------------
// DELETE /api/v1/mailboxes/:mailboxId/acl/members/:memberEmail
// ---------------------------------------------------------------------------

describe("DELETE /acl/members/:memberEmail — remove member", () => {
	it("owner removes an existing member → 200 with updated ACL", async () => {
		const { fetch, bucket } = makeApp(storeWithAcl(aliceAndBobAcl), "alice@example.com");
		const res = await fetch(
			`/api/v1/mailboxes/${mailboxId}/acl/members/bob@example.com`,
			{ method: "DELETE" },
		);
		expect(res.status).toBe(200);
		const body = await res.json() as MailboxAcl;
		expect(body.members).not.toContain("bob@example.com");
		// Persisted to R2
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.members).not.toContain("bob@example.com");
	});

	it("DELETE on owner's own email → 400", async () => {
		const { fetch } = makeApp(storeWithAcl(aliceOnlyAcl), "alice@example.com");
		const res = await fetch(
			`/api/v1/mailboxes/${mailboxId}/acl/members/alice@example.com`,
			{ method: "DELETE" },
		);
		expect(res.status).toBe(400);
		const body = await res.json() as { error: string };
		expect(body.error).toBeTruthy();
	});

	it("non-owner admitted caller → 403", async () => {
		// Bob is in members (requireMailbox passes) but is not the owner.
		const { fetch } = makeApp(storeWithAcl(aliceAndBobAcl), "bob@example.com");
		const res = await fetch(
			`/api/v1/mailboxes/${mailboxId}/acl/members/bob@example.com`,
			{ method: "DELETE" },
		);
		expect(res.status).toBe(403);
	});

	it("email path param is URL-decoded and normalised to lower-case", async () => {
		const { fetch, bucket } = makeApp(storeWithAcl(aliceAndBobAcl), "alice@example.com");
		// Percent-encoded uppercase email in the path
		const encoded = encodeURIComponent("BOB@EXAMPLE.COM");
		const res = await fetch(
			`/api/v1/mailboxes/${mailboxId}/acl/members/${encoded}`,
			{ method: "DELETE" },
		);
		expect(res.status).toBe(200);
		const stored = JSON.parse(bucket._store[aclKey]) as MailboxAcl;
		expect(stored.members).not.toContain("bob@example.com");
	});
});
