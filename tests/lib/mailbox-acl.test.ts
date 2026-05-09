// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { callerInAcl, readMailboxAcl, writeMailboxAcl, deleteMailboxAcl } from "../../workers/lib/mailbox-acl";
import type { MailboxAcl } from "../../workers/lib/mailbox-acl";
import { requireMailbox } from "../../workers/lib/mailbox";

// ---------------------------------------------------------------------------
// callerInAcl — pure function, no mocking needed
// ---------------------------------------------------------------------------

describe("callerInAcl", () => {
	it("returns true when acl is null (backwards-compat, no ACL written yet)", () => {
		expect(callerInAcl(null, "alice@example.com")).toBe(true);
		expect(callerInAcl(null, null)).toBe(true);
	});

	it("returns true when callerEmail is falsy (dev mode, no Access in front)", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, null)).toBe(true);
		expect(callerInAcl(acl, "")).toBe(true);
		expect(callerInAcl(acl, undefined)).toBe(true);
	});

	it("returns true when caller is in members list", () => {
		const acl: MailboxAcl = {
			owner: "alice@example.com",
			members: ["alice@example.com", "bob@example.com"],
		};
		expect(callerInAcl(acl, "alice@example.com")).toBe(true);
		expect(callerInAcl(acl, "bob@example.com")).toBe(true);
	});

	it("returns false when caller is not in members list", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, "eve@example.com")).toBe(false);
	});

	it("comparison is case-insensitive", () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		expect(callerInAcl(acl, "ALICE@EXAMPLE.COM")).toBe(true);
		expect(callerInAcl(acl, "Alice@Example.Com")).toBe(true);
		expect(callerInAcl(acl, "EVE@EXAMPLE.COM")).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// readMailboxAcl / writeMailboxAcl / deleteMailboxAcl — in-memory R2 stub
// ---------------------------------------------------------------------------

function makeR2Stub(initial: Record<string, string> = {}) {
	const store = { ...initial };
	return {
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

describe("readMailboxAcl", () => {
	it("returns null when no ACL blob exists", async () => {
		const bucket = makeR2Stub();
		const result = await readMailboxAcl({ BUCKET: bucket as unknown as R2Bucket }, "user@example.com");
		expect(result).toBeNull();
	});

	it("returns the parsed ACL when present", async () => {
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		const bucket = makeR2Stub({
			"mailboxes-acl/user@example.com.json": JSON.stringify(acl),
		});
		const result = await readMailboxAcl({ BUCKET: bucket as unknown as R2Bucket }, "user@example.com");
		expect(result).toEqual(acl);
	});

	it("returns null when the blob is malformed JSON", async () => {
		const bucket = makeR2Stub({ "mailboxes-acl/user@example.com.json": "not-json" });
		const result = await readMailboxAcl({ BUCKET: bucket as unknown as R2Bucket }, "user@example.com");
		expect(result).toBeNull();
	});
});

describe("writeMailboxAcl + deleteMailboxAcl", () => {
	it("writes then reads back the ACL", async () => {
		const bucket = makeR2Stub();
		const env = { BUCKET: bucket as unknown as R2Bucket };
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		await writeMailboxAcl(env, "alice@example.com", acl);
		const read = await readMailboxAcl(env, "alice@example.com");
		expect(read).toEqual(acl);
	});

	it("deleteMailboxAcl removes the blob so readMailboxAcl returns null", async () => {
		const bucket = makeR2Stub();
		const env = { BUCKET: bucket as unknown as R2Bucket };
		const acl: MailboxAcl = { owner: "alice@example.com", members: ["alice@example.com"] };
		await writeMailboxAcl(env, "alice@example.com", acl);
		await deleteMailboxAcl(env, "alice@example.com");
		const read = await readMailboxAcl(env, "alice@example.com");
		expect(read).toBeNull();
	});
});

// ---------------------------------------------------------------------------
// requireMailbox — inline Hono app with stub R2 + DO namespace
// ---------------------------------------------------------------------------

function makeFullR2Stub(initial: Record<string, string> = {}) {
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
	};
}

function makeFakeMailboxApp(
	bucketStore: Record<string, string>,
	callerEmail: string | null,
) {
	const bucket = makeFullR2Stub(bucketStore);
	// Minimal DO namespace stub — just needs idFromName / get
	const mailboxStub = { id: "fake-do-id" };
	const MAILBOX = {
		idFromName: (_name: string) => "fake-id",
		get: (_id: unknown) => mailboxStub,
	};

	const app = new Hono<{ Bindings: { BUCKET: typeof bucket; MAILBOX: typeof MAILBOX } }>();

	app.use("/mailboxes/:mailboxId/*", requireMailbox as Parameters<typeof app.use>[1]);

	app.get("/mailboxes/:mailboxId/test", (c) => c.json({ ok: true }));

	return {
		fetch: (path: string) => {
			const headers: Record<string, string> = {};
			if (callerEmail) headers["cf-access-authenticated-user-email"] = callerEmail;
			return app.request(path, { headers }, { BUCKET: bucket as unknown as R2Bucket, MAILBOX: MAILBOX as unknown as DurableObjectNamespace });
		},
	};
}

describe("requireMailbox — ACL enforcement", () => {
	const mailboxKey = "mailboxes/alice@example.com.json";
	const aclKey = "mailboxes-acl/alice@example.com.json";
	const aliceAcl: MailboxAcl = {
		owner: "alice@example.com",
		members: ["alice@example.com"],
	};

	it("returns 404 when mailbox does not exist", async () => {
		const app = makeFakeMailboxApp({}, "alice@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(404);
	});

	it("allows access when no ACL is set (backwards-compat)", async () => {
		const store = { [mailboxKey]: "{}" };
		const app = makeFakeMailboxApp(store, "anyone@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("allows access when callerEmail matches ACL", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, "alice@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("returns 403 when callerEmail is not in ACL", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, "eve@example.com");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(403);
	});

	it("allows access in dev mode (no callerEmail) regardless of ACL", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, null);
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});

	it("ACL comparison is case-insensitive", async () => {
		const store = {
			[mailboxKey]: "{}",
			[aclKey]: JSON.stringify(aliceAcl),
		};
		const app = makeFakeMailboxApp(store, "ALICE@EXAMPLE.COM");
		const res = await app.fetch("/mailboxes/alice@example.com/test");
		expect(res.status).toBe(200);
	});
});
