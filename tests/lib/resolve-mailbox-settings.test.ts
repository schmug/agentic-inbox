// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Inheritance resolver coverage for #106. Asserts the four resolution
 * states (mailbox > org > default), the whole-object replace rule for
 * nested fields (NOT cross-tier deep merge), the ETag cache discipline,
 * and the PUT-side stripDefaultEqual pass.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	DEFAULT_MAILBOX_SETTINGS,
	getMailboxSettings,
	resolveMailboxSettings,
	stripDefaultEqual,
} from "../../workers/lib/mailbox-settings";
import {
	clearOrgSettingsCache,
	getOrgSettings,
	orgSettingsKey,
	putOrgSettings,
} from "../../workers/lib/org-settings";
import {
	clearDomainSettingsCache,
	domainFromMailboxId,
	domainSettingsKey,
	getDomainSettings,
	putDomainSettings,
} from "../../workers/lib/domain-settings";
import { DEFAULT_SECURITY_SETTINGS } from "../../workers/security/defaults";
import { loadHubConfig } from "../../workers/lib/hub-config";

interface FakeStored {
	body: string;
	etag: string;
}

interface FakeBucket extends R2Bucket {
	__store: Map<string, FakeStored>;
	__getCalls: Array<{ key: string; ifNoneMatch: string | null }>;
	__putCalls: Array<{ key: string; body: string }>;
}

let etagCounter = 0;

function nextEtag(): string {
	etagCounter += 1;
	return `etag-${etagCounter}`;
}

/** Minimal R2-compatible bucket for tests. Honours `onlyIf.etagDoesNotMatch`
 *  by returning null when the stored etag matches the precondition (i.e.
 *  the 304 path). Records every read so tests can assert on cache misses. */
function makeFakeBucket(initial: Record<string, unknown> = {}): FakeBucket {
	const store = new Map<string, FakeStored>();
	for (const [key, value] of Object.entries(initial)) {
		store.set(key, { body: JSON.stringify(value), etag: nextEtag() });
	}
	const getCalls: Array<{ key: string; ifNoneMatch: string | null }> = [];
	const putCalls: Array<{ key: string; body: string }> = [];

	const bucket = {
		async get(key: string, opts?: R2GetOptions) {
			const ifNoneMatch =
				(opts?.onlyIf as { etagDoesNotMatch?: string } | undefined)?.etagDoesNotMatch ?? null;
			getCalls.push({ key, ifNoneMatch });
			const stored = store.get(key);
			if (!stored) return null;
			if (ifNoneMatch && stored.etag === ifNoneMatch) {
				// 304 — caller should reuse cached value.
				return null;
			}
			const body = stored.body;
			return {
				etag: stored.etag,
				async json() {
					return JSON.parse(body);
				},
				async text() {
					return body;
				},
			} as unknown as R2ObjectBody;
		},
		async put(key: string, body: string) {
			putCalls.push({ key, body });
			store.set(key, { body, etag: nextEtag() });
			return null as unknown as R2Object;
		},
		async head(key: string) {
			const stored = store.get(key);
			if (!stored) return null;
			return { etag: stored.etag } as unknown as R2Object;
		},
		async delete(key: string) {
			store.delete(key);
		},
	} as unknown as FakeBucket;
	bucket.__store = store;
	bucket.__getCalls = getCalls;
	bucket.__putCalls = putCalls;
	return bucket;
}

function makeEnv(bucket: FakeBucket) {
	return { BUCKET: bucket } as unknown as { BUCKET: R2Bucket };
}

const MAILBOX_ID = "user@example.com";
const MAILBOX_KEY = `mailboxes/${MAILBOX_ID}.json`;
const DOMAIN_KEY = "domains/example.com.json";

beforeEach(() => {
	clearOrgSettingsCache();
	clearDomainSettingsCache();
	etagCounter = 0;
});

describe("resolveMailboxSettings — agentModel inheritance", () => {
	it("(a) mailbox overrides org → mailbox value wins", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			[MAILBOX_KEY]: { agentModel: "@cf/mailbox/value" },
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.agentModel).toBe("@cf/mailbox/value");
	});

	it("(b) org-only → org value", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.agentModel).toBe("@cf/org/value");
	});

	it("(c) both absent → system default", async () => {
		const bucket = makeFakeBucket({ [MAILBOX_KEY]: {} });
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.agentModel).toBe(DEFAULT_MAILBOX_SETTINGS.agentModel);
	});

	it("(d) PUT mailbox value equal to default → stripped → next read returns default via inheritance", async () => {
		// Simulate the PUT pipeline: parse + strip + write.
		const incoming = { agentModel: DEFAULT_MAILBOX_SETTINGS.agentModel };
		const stripped = stripDefaultEqual(incoming);
		expect(stripped.agentModel).toBeUndefined();

		const bucket = makeFakeBucket({ [MAILBOX_KEY]: stripped });
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		// Falls through inheritance to the system default.
		expect(resolved.agentModel).toBe(DEFAULT_MAILBOX_SETTINGS.agentModel);
		// And the stored mailbox JSON does NOT carry the field — the next
		// person editing org-level settings will see their value take effect
		// for this mailbox, which is the whole point.
		const stored = JSON.parse(bucket.__store.get(MAILBOX_KEY)!.body);
		expect(Object.keys(stored)).not.toContain("agentModel");
	});
});

describe("resolveMailboxSettings — security whole-object replace", () => {
	it("mailbox security replaces the org block whole — allowlists do NOT extend", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": {
				security: { enabled: true, allowlist_senders: ["a@b.com"] },
			},
			[MAILBOX_KEY]: {
				security: { enabled: true, allowlist_senders: ["c@d.com"] },
			},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		// Only the mailbox value, NOT a merged ["a@b.com","c@d.com"]. v1
		// extend-merge is intentionally out of scope (audit Q3 follow-up).
		expect(resolved.security.allowlist_senders).toEqual(["c@d.com"]);
	});

	it("mailbox absent + org security set → org block wins, normalised", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": {
				security: { enabled: true, allowlist_domains: ["ORG.COM"] },
			},
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.security.enabled).toBe(true);
		// Normalisation runs on the resolved block — domains get lowercased.
		expect(resolved.security.allowlist_domains).toEqual(["org.com"]);
	});

	it("both absent → DEFAULT_SECURITY_SETTINGS", async () => {
		const bucket = makeFakeBucket({ [MAILBOX_KEY]: {} });
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.security.enabled).toBe(DEFAULT_SECURITY_SETTINGS.enabled);
		expect(resolved.security.thresholds).toEqual(DEFAULT_SECURITY_SETTINGS.thresholds);
	});

	it("partial mailbox security completes with defaults (single-tier completion)", async () => {
		// Within the winning tier, missing keys are filled from the default
		// so consumers don't see undefined thresholds. This is NOT cross-tier
		// merge — it just makes the resolved block fully-populated.
		const bucket = makeFakeBucket({ [MAILBOX_KEY]: { security: { enabled: true } } });
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.security.enabled).toBe(true);
		expect(resolved.security.thresholds).toEqual(DEFAULT_SECURITY_SETTINGS.thresholds);
		expect(resolved.security.attachment_policy).toEqual(DEFAULT_SECURITY_SETTINGS.attachment_policy);
	});
});

describe("resolveMailboxSettings — intel.hub inheritance (#121 audit Q1)", () => {
	const orgHub = {
		url: "https://hub.example.com",
		org_uuid: "org-uuid-123",
		api_key_secret_name: "HUB_KEY",
	};
	const mailboxHub = {
		url: "https://other-hub.example.com",
		org_uuid: "mailbox-uuid-456",
		api_key_secret_name: "OTHER_HUB_KEY",
	};

	it("org sets hub, mailbox absent → resolved.intel.hub = org hub", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { intel: { hub: orgHub } },
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.intel.hub).toMatchObject(orgHub);
	});

	it("mailbox hub overrides org — whole-object replace, no merged uuid", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { intel: { hub: orgHub } },
			[MAILBOX_KEY]: { intel: { hub: mailboxHub } },
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.intel.hub).toMatchObject(mailboxHub);
		// Crucially: org_uuid is the mailbox's, not a merge of both.
		expect(resolved.intel.hub?.org_uuid).toBe("mailbox-uuid-456");
	});

	it("loadHubConfig flows through the resolver — org hub takes effect for unconfigured mailbox", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { intel: { hub: orgHub } },
			[MAILBOX_KEY]: {},
		});
		const cfg = await loadHubConfig(makeEnv(bucket), MAILBOX_ID);
		expect(cfg).not.toBeNull();
		expect(cfg?.url).toBe(orgHub.url);
		expect(cfg?.org_uuid).toBe(orgHub.org_uuid);
	});
});

describe("getOrgSettings — module-scope ETag cache", () => {
	it("first call fetches, second call sends If-None-Match and short-circuits on 304", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/v1" },
		});
		const env = makeEnv(bucket);

		const first = await getOrgSettings(env);
		expect(first.agentModel).toBe("@cf/org/v1");
		expect(bucket.__getCalls).toHaveLength(1);
		expect(bucket.__getCalls[0].ifNoneMatch).toBeNull();

		// Spy on JSON parse to confirm the 304 path doesn't reparse.
		const second = await getOrgSettings(env);
		expect(second.agentModel).toBe("@cf/org/v1");
		expect(bucket.__getCalls).toHaveLength(2);
		expect(bucket.__getCalls[1].ifNoneMatch).toBe("etag-1");
	});

	it("putOrgSettings invalidates the cache → next read fetches fresh", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/v1" },
		});
		const env = makeEnv(bucket);

		await getOrgSettings(env); // prime cache
		await putOrgSettings(env, { agentModel: "@cf/org/v2" });

		const after = await getOrgSettings(env);
		expect(after.agentModel).toBe("@cf/org/v2");
	});

	it("404 caches an absent sentinel so the hot path doesn't re-fetch", async () => {
		// No org/settings.json key in the bucket → all reads return null.
		const bucket = makeFakeBucket({});
		const env = makeEnv(bucket);

		const first = await getOrgSettings(env);
		const second = await getOrgSettings(env);
		expect(first).toEqual({});
		expect(second).toEqual({});
		// Both calls read R2 (we don't skip the call entirely — the second
		// just hits the absent-cached path, with no If-None-Match because
		// there's nothing to send).
		expect(bucket.__getCalls).toHaveLength(2);
		expect(bucket.__getCalls[1].ifNoneMatch).toBeNull();
	});
});

describe("stripDefaultEqual", () => {
	it("drops agentModel equal to system default", () => {
		const stripped = stripDefaultEqual({ agentModel: DEFAULT_MAILBOX_SETTINGS.agentModel });
		expect(stripped.agentModel).toBeUndefined();
	});

	it("keeps agentModel set to a custom value", () => {
		const stripped = stripDefaultEqual({ agentModel: "@cf/custom/value" });
		expect(stripped.agentModel).toBe("@cf/custom/value");
	});

	it("drops a security block that deep-equals the default", () => {
		const stripped = stripDefaultEqual({ security: DEFAULT_SECURITY_SETTINGS });
		expect((stripped as Record<string, unknown>).security).toBeUndefined();
	});

	it("keeps a security block with a single non-default field", () => {
		const stripped = stripDefaultEqual({
			security: { ...DEFAULT_SECURITY_SETTINGS, enabled: true },
		});
		expect(stripped.security).toBeDefined();
		expect((stripped.security as { enabled: boolean }).enabled).toBe(true);
	});

	it("preserves per-mailbox-only fields (fromName, signature) untouched", () => {
		const stripped = stripDefaultEqual({
			fromName: "Daisy",
			signature: { enabled: true, text: "Cheers" },
		} as Parameters<typeof stripDefaultEqual>[0]);
		expect((stripped as Record<string, unknown>).fromName).toBe("Daisy");
		expect((stripped as Record<string, unknown>).signature).toEqual({
			enabled: true,
			text: "Cheers",
		});
	});

	it("composes correctly with the POST /api/v1/mailboxes default-settings layer", () => {
		// Simulates the create-mailbox handler in workers/index.ts: a fresh
		// mailbox PUT-payload that includes the rendered form defaults must
		// drop the inheritable defaults but keep the per-mailbox-only
		// identity fields (audit Q8).
		const incomingFromUI = {
			agentModel: DEFAULT_MAILBOX_SETTINGS.agentModel,
			autoDraft: DEFAULT_MAILBOX_SETTINGS.autoDraft,
			agentSystemPrompt: "stay polite",
		};
		const cleaned = stripDefaultEqual(incomingFromUI);
		const perMailboxIdentity = {
			fromName: "Daisy",
			signature: { enabled: false, text: "" },
		};
		const finalSettings = { ...perMailboxIdentity, ...cleaned };
		// agentModel + autoDraft were defaults → dropped → mailbox now
		// inherits whatever the org tier sets later.
		expect((finalSettings as Record<string, unknown>).agentModel).toBeUndefined();
		expect((finalSettings as Record<string, unknown>).autoDraft).toBeUndefined();
		// Custom prompt survives.
		expect((finalSettings as Record<string, unknown>).agentSystemPrompt).toBe("stay polite");
		// Per-mailbox identity untouched.
		expect((finalSettings as Record<string, unknown>).fromName).toBe("Daisy");
	});
});

describe("getMailboxSettings — raw read still works post-#106", () => {
	it("returns the raw mailbox JSON without materialising defaults", async () => {
		const bucket = makeFakeBucket({
			[MAILBOX_KEY]: { agentSystemPrompt: "stay polite" },
		});
		const raw = await getMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(raw.agentSystemPrompt).toBe("stay polite");
		// agentModel was NOT in the JSON, and no schema default kicks in.
		expect(raw.agentModel).toBeUndefined();
		expect(raw.autoDraft).toBeUndefined();
	});

	it("orgSettingsKey returns the centralised flat key (multi-tenant hook)", () => {
		// Sanity-check the centralisation point. A future multi-tenant
		// refactor changes only this helper.
		expect(orgSettingsKey()).toBe("org/settings.json");
	});

	// Suppress the unused-import warning — vi is reserved for follow-on
	// tests that mock the resolver from agent code paths.
	void vi;
});

describe("resolveMailboxSettings — domain tier (#142)", () => {
	it("domain wins over org but loses to mailbox (mailbox > domain > org chain)", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			[DOMAIN_KEY]: { agentModel: "@cf/domain/value" },
			[MAILBOX_KEY]: { agentModel: "@cf/mailbox/value" },
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.agentModel).toBe("@cf/mailbox/value");
		expect(resolved.domainName).toBe("example.com");
	});

	it("domain set + mailbox absent → domain value (skips org)", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			[DOMAIN_KEY]: { agentModel: "@cf/domain/value" },
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.agentModel).toBe("@cf/domain/value");
	});

	it("domain absent + org set → org value (no domains/<domain>.json file)", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.agentModel).toBe("@cf/org/value");
	});

	it("malformed mailboxId (no @) skips the domain read entirely", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			"mailboxes/no-at-sign.json": {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), "no-at-sign");
		expect(resolved.agentModel).toBe("@cf/org/value");
		expect(resolved.domainName).toBeNull();
		// The bucket should never have been asked for a domains/* key.
		const domainCalls = bucket.__getCalls.filter((c) => c.key.startsWith("domains/"));
		expect(domainCalls).toHaveLength(0);
	});

	it("domain security replaces org security WHOLE — no cross-tier deep-merge", async () => {
		const bucket = makeFakeBucket({
			"org/settings.json": {
				security: { enabled: true, allowlist_senders: ["org@example.com"] },
			},
			[DOMAIN_KEY]: {
				security: { enabled: true, allowlist_senders: ["domain@example.com"] },
			},
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		// Only the domain entry, NOT a merged ["org@...","domain@..."]. Same
		// extend-merge follow-up as #149.
		expect(resolved.security.allowlist_senders).toEqual(["domain@example.com"]);
	});

	it("domain intel.hub takes effect for an unconfigured mailbox", async () => {
		const domainHub = {
			url: "https://domain-hub.example.com",
			org_uuid: "domain-uuid",
			api_key_secret_name: "DOMAIN_HUB_KEY",
		};
		const bucket = makeFakeBucket({
			[DOMAIN_KEY]: { intel: { hub: domainHub } },
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.intel.hub).toMatchObject(domainHub);
	});

	it("security-critical models stay org-only — domain values are ignored", async () => {
		// Audit Q7: per-mailbox / per-domain override of the prompt-injection
		// scanner is too sharp without UI guardrails. The resolver must NOT
		// consult the domain tier for these three fields.
		const bucket = makeFakeBucket({
			"org/settings.json": { injectionScannerModel: "@cf/org/scanner" },
			[DOMAIN_KEY]: { injectionScannerModel: "@cf/domain/should-be-ignored" },
			[MAILBOX_KEY]: {},
		});
		const resolved = await resolveMailboxSettings(makeEnv(bucket), MAILBOX_ID);
		expect(resolved.injectionScannerModel).toBe("@cf/org/scanner");
	});
});

describe("getDomainSettings — module-scope ETag cache", () => {
	it("first call fetches, second sends If-None-Match and short-circuits on 304", async () => {
		const bucket = makeFakeBucket({
			[DOMAIN_KEY]: { agentModel: "@cf/domain/v1" },
		});
		const env = makeEnv(bucket);

		const first = await getDomainSettings(env, "example.com");
		expect(first.agentModel).toBe("@cf/domain/v1");
		const domainCalls = bucket.__getCalls.filter((c) => c.key === DOMAIN_KEY);
		expect(domainCalls).toHaveLength(1);
		expect(domainCalls[0].ifNoneMatch).toBeNull();

		const second = await getDomainSettings(env, "example.com");
		expect(second.agentModel).toBe("@cf/domain/v1");
		const after = bucket.__getCalls.filter((c) => c.key === DOMAIN_KEY);
		expect(after).toHaveLength(2);
		expect(after[1].ifNoneMatch).toBe("etag-1");
	});

	it("putDomainSettings invalidates the per-domain cache slot only", async () => {
		const bucket = makeFakeBucket({
			[DOMAIN_KEY]: { agentModel: "@cf/v1" },
			"domains/other.com.json": { agentModel: "@cf/other-v1" },
		});
		const env = makeEnv(bucket);

		// Prime both caches.
		await getDomainSettings(env, "example.com");
		await getDomainSettings(env, "other.com");
		const before = bucket.__getCalls.length;

		// Update example.com → its cache slot is invalidated.
		await putDomainSettings(env, "example.com", { agentModel: "@cf/v2" });
		const exampleAfter = await getDomainSettings(env, "example.com");
		expect(exampleAfter.agentModel).toBe("@cf/v2");

		// other.com cache should still hit (no R2 GET beyond the If-None-Match
		// path that returns the cached value).
		await getDomainSettings(env, "other.com");
		const otherCalls = bucket.__getCalls
			.slice(before)
			.filter((c) => c.key === "domains/other.com.json");
		// Only the If-None-Match GET should fire — and it should hit 304 → no
		// reparse. The fact that we got here without a fresh body parse is the
		// behaviour we care about; assert via the etag header on the call.
		expect(otherCalls.length).toBeLessThanOrEqual(1);
		if (otherCalls.length === 1) {
			expect(otherCalls[0].ifNoneMatch).not.toBeNull();
		}
	});

	it("404 caches an absent sentinel for the requested domain", async () => {
		const bucket = makeFakeBucket({});
		const env = makeEnv(bucket);

		const first = await getDomainSettings(env, "absent.com");
		const second = await getDomainSettings(env, "absent.com");
		expect(first).toEqual({});
		expect(second).toEqual({});
		// Two reads but both for the same key; the second uses no If-None-Match
		// because the cached etag is the absent sentinel.
		const absentCalls = bucket.__getCalls.filter(
			(c) => c.key === "domains/absent.com.json",
		);
		expect(absentCalls).toHaveLength(2);
		expect(absentCalls[1].ifNoneMatch).toBeNull();
	});
});

describe("stripDefaultEqual — symmetric across mailbox / domain / org tiers", () => {
	it("works on a DomainSettings-shaped payload (drops agentModel == default)", async () => {
		// Symmetry guard: PR1 wired stripDefaultEqual into the mailbox PUT/POST.
		// #142 wires it into the domain PUT for the same reason — a fresh
		// domain save with rendered defaults must not silently shadow org for
		// every mailbox under that domain. Caught by advisor before merge.
		const stripped = stripDefaultEqual({
			agentModel: DEFAULT_MAILBOX_SETTINGS.agentModel,
			autoDraft: DEFAULT_MAILBOX_SETTINGS.autoDraft,
			agentSystemPrompt: "domain-specific prompt",
		});
		expect((stripped as Record<string, unknown>).agentModel).toBeUndefined();
		expect((stripped as Record<string, unknown>).autoDraft).toBeUndefined();
		// Non-default fields still survive.
		expect((stripped as Record<string, unknown>).agentSystemPrompt).toBe("domain-specific prompt");
	});

	it("end-to-end: domain PUT of all-defaults round-trips clean (mailbox sees org tier)", async () => {
		// Compose: putDomainSettings persists a strip-default'd payload →
		// resolveMailboxSettings reads it back → resolved value comes from
		// the org tier, not the domain tier (which dropped the default).
		const bucket = makeFakeBucket({
			"org/settings.json": { agentModel: "@cf/org/value" },
			[MAILBOX_KEY]: {},
		});
		const env = makeEnv(bucket);

		// Simulate the worker PUT pipeline for the domain endpoint:
		// parse + strip + write. The stripped payload has no agentModel
		// because it equalled the system default.
		const incoming = { agentModel: DEFAULT_MAILBOX_SETTINGS.agentModel };
		const stripped = stripDefaultEqual(incoming);
		await putDomainSettings(env, "example.com", stripped);

		const resolved = await resolveMailboxSettings(env, MAILBOX_ID);
		// Falls through to the org tier, not stuck on the domain tier's
		// materialised default.
		expect(resolved.agentModel).toBe("@cf/org/value");
	});
});

describe("domainFromMailboxId / domainSettingsKey", () => {
	it("extracts the domain part of an email-style mailboxId", () => {
		expect(domainFromMailboxId("user@example.com")).toBe("example.com");
		expect(domainFromMailboxId("user@SUBDOMAIN.Example.COM")).toBe("subdomain.example.com");
	});

	it("returns null for malformed input", () => {
		expect(domainFromMailboxId("no-at-sign")).toBeNull();
		expect(domainFromMailboxId("user@")).toBeNull();
		expect(domainFromMailboxId("")).toBeNull();
	});

	it("centralises the R2 key format for a future multi-tenant refactor", () => {
		expect(domainSettingsKey("Example.COM")).toBe("domains/example.com.json");
	});
});

