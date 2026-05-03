// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * CrowdSec community blocklist coverage.
 *
 * The blocklist ships as plain-IP-per-line (with optional CIDRs and `#`
 * comment lines). It rides the same `ip-cidr` storage / lookup path as
 * Spamhaus DROP — `parseCidrFeedBody` already treats a bare IP as a `/32`
 * via `parseCidr`. This test file targets the new default feed
 * (`crowdsec-community`) end-to-end:
 *
 *   1. Parser — bare IPs become `/32`, CIDRs round-trip, `#` comments and
 *      malformed lines are warn-and-skipped (never throw).
 *   2. Lookup — `checkIpAgainstFeeds` reports the new feed id when the
 *      resolved IP is inside an entry, and the lookup label renders as
 *      "CrowdSec Community Blocklist" (description left-of-em-dash) so the
 *      operator-facing reason string contains the recognizable name.
 *   3. Integration — `runDeepScan` with a redirect target whose A-record
 *      sits in the blocklist surfaces the new reason and contributes the
 *      IP-feed score bump, with no CTI key configured.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
	checkIpAgainstFeeds,
	parseCidrFeedBody,
} from "../../workers/intel/feeds";
import { runDeepScan } from "../../workers/intel/deep-scan";
import { DEFAULT_FEEDS } from "../../workers/intel/defaults";
import type { Env } from "../../workers/types";

const FIXTURE_PATH = resolve(
	__dirname,
	"../fixtures/security/crowdsec-community.txt",
);
const FIXTURE = readFileSync(FIXTURE_PATH, "utf8");

const FEED_ID = "crowdsec-community";

// ── Test KV / mailbox stub helpers (mirror spamhaus-drop.test.ts) ─────

interface FakeKv {
	store: Map<string, string>;
	get: (key: string, type?: "text" | "arrayBuffer") => Promise<string | null>;
	put: (
		key: string,
		value: string,
		opts?: { expirationTtl?: number },
	) => Promise<void>;
}

function makeKv(): FakeKv {
	const store = new Map<string, string>();
	return {
		store,
		async get(key) {
			return store.get(key) ?? null;
		},
		async put(key, value) {
			store.set(key, value);
		},
	};
}

interface FakeBucket {
	get: (key: string) => Promise<{ json: () => Promise<unknown> } | null>;
}

function makeBucket(mailboxJson: unknown): FakeBucket {
	return {
		async get(_key: string) {
			return {
				async json() {
					return mailboxJson;
				},
			};
		},
	};
}

interface FakeUrlRow {
	id: string;
	url: string;
	resolved_url?: string | null;
}

function makeStub(urls: FakeUrlRow[]) {
	const stub = {
		async getStoredVerdict(_emailId: string) {
			return {
				verdict: JSON.stringify({
					action: "tag",
					score: 30,
					triage: "score",
					signals: ["base"],
					explanation: "base",
				}),
				score: 30,
			};
		},
		async getUrlsForEmail(_emailId: string) {
			return urls;
		},
		async updateUrlScan() {},
		async getAttachmentsForEmail() {
			return [];
		},
		async updateAttachmentScan() {},
		async persistSecurityVerdict() {},
		async moveEmail() {},
		async updateDeepScanStatus() {},
	};
	return { stub };
}

function makeEnv(opts: {
	apiKey?: string;
	kv?: FakeKv;
	bucket?: FakeBucket;
	stub: unknown;
}): Env {
	const mailboxNs = {
		idFromName(_n: string) {
			return { toString: () => _n } as unknown as DurableObjectId;
		},
		get(_id: DurableObjectId) {
			return opts.stub as unknown as DurableObjectStub;
		},
	} as unknown as DurableObjectNamespace;
	return {
		CROWDSEC_CTI_API_KEY: opts.apiKey,
		BLOOM_KV: opts.kv as unknown as KVNamespace | undefined,
		BUCKET: opts.bucket as unknown as R2Bucket | undefined,
		MAILBOX: mailboxNs,
	} as unknown as Env;
}

function makeFetchMock(
	handlers: Array<(url: string) => Response | Promise<Response> | null>,
) {
	return vi.fn(async (input: string | URL | Request) => {
		const url = typeof input === "string" ? input : input.toString();
		for (const h of handlers) {
			const out = await h(url);
			if (out) return out;
		}
		return new Response("not mocked: " + url, { status: 404 });
	});
}

/**
 * Materialise the fixture into the fake KV under the new feed's storage key,
 * matching the JSON shape `feeds.ts` writes during refresh.
 */
function seedCrowdsecFeed(kv: FakeKv): void {
	const cidrs = parseCidrFeedBody(FIXTURE, FEED_ID);
	const serialized = JSON.stringify(
		cidrs.map((c) => ({ n: c.network, m: c.mask, p: c.prefix })),
	);
	kv.store.set(`intel:${FEED_ID}:cidrs`, serialized);
}

// ── Default-feed registration ─────────────────────────────────────────

describe("DEFAULT_FEEDS includes the CrowdSec community blocklist", () => {
	it("registers a placeholder ip-cidr entry whose description renders to a recognizable label", () => {
		const def = DEFAULT_FEEDS.find((f) => f.id === FEED_ID);
		expect(def).toBeDefined();
		expect(def?.kind).toBe("ip-cidr");
		// URL is intentionally a placeholder (operator-configured). The
		// `resolveFeeds` filter skips empty URLs at refresh time so the cron
		// doesn't spam fetch failures on default deploys.
		expect(def?.url).toBe("");
		// `feedDisplayName` takes the segment before the em-dash. The label
		// is operator-facing; it must be the recognizable product name, not
		// the bare feed id, when the lookup fires.
		expect(def?.description.split("—")[0].trim()).toBe(
			"CrowdSec Community Blocklist",
		);
	});
});

// ── Parser tests ──────────────────────────────────────────────────────

describe("parseCidrFeedBody (CrowdSec community)", () => {
	it("treats bare IPs as /32, keeps CIDRs, skips `#` comments and malformed lines", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const cidrs = parseCidrFeedBody(FIXTURE, FEED_ID);
			// Fixture contains 4 valid entries: 198.51.100.7, 198.51.100.8,
			// 203.0.113.0/24, 192.0.2.99. The "not-an-ip" line is malformed
			// and must be skipped.
			expect(cidrs.length).toBe(4);
			// First two are bare IPs → /32.
			expect(cidrs[0]).toEqual(expect.objectContaining({ prefix: 32 }));
			expect(cidrs[1]).toEqual(expect.objectContaining({ prefix: 32 }));
			expect(cidrs[2]).toEqual(expect.objectContaining({ prefix: 24 }));
			expect(cidrs[3]).toEqual(expect.objectContaining({ prefix: 32 }));
			// Malformed entry must warn, not throw.
			expect(warn).toHaveBeenCalled();
			expect(
				warn.mock.calls.some((c) => String(c[0]).includes("not-an-ip")),
			).toBe(true);
		} finally {
			warn.mockRestore();
		}
	});
});

// ── Lookup tests ──────────────────────────────────────────────────────

describe("checkIpAgainstFeeds (CrowdSec community)", () => {
	it("returns a match for a bare IP listed as /32", async () => {
		const kv = makeKv();
		seedCrowdsecFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		const match = await checkIpAgainstFeeds(env, "m@x", "198.51.100.7");
		expect(match).not.toBeNull();
		expect(match?.feedId).toBe(FEED_ID);
		expect(match?.cidr).toBe("198.51.100.7/32");
		// The feedDescription must contain the recognizable product name so
		// `feedDisplayName` in deep-scan renders the operator-facing label.
		expect(match?.feedDescription).toMatch(/CrowdSec Community Blocklist/);
	});

	it("returns a match for an IP inside a /24 entry", async () => {
		const kv = makeKv();
		seedCrowdsecFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		const match = await checkIpAgainstFeeds(env, "m@x", "203.0.113.42");
		expect(match?.feedId).toBe(FEED_ID);
		expect(match?.cidr).toBe("203.0.113.0/24");
	});

	it("returns null for an IP outside every entry", async () => {
		const kv = makeKv();
		seedCrowdsecFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		expect(
			await checkIpAgainstFeeds(env, "m@x", "8.8.8.8"),
		).toBeNull();
	});
});

// ── Integration with runDeepScan ──────────────────────────────────────

describe("runDeepScan + CrowdSec community blocklist", () => {
	let originalFetch: typeof fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});
	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.restoreAllMocks();
	});

	it("redirect target IP listed in the blocklist surfaces the new reason and bumps the score", async () => {
		const fetchMock = makeFetchMock([
			(url) => {
				if (new URL(url).hostname === "phish.example.com") {
					return new Response(
						"<html><title>Login</title></html>",
						{ status: 200, headers: { "content-type": "text/html" } },
					);
				}
				return null;
			},
			// RDAP — empty payload, no contribution.
			(url) =>
				new URL(url).hostname === "rdap.org"
					? new Response("{}", { status: 200 })
					: null,
			// DoH resolves the redirect host to an IP listed in the fixture.
			(url) => {
				const parsed = new URL(url);
				if (
					parsed.hostname === "cloudflare-dns.com" &&
					parsed.pathname.startsWith("/dns-query")
				) {
					return new Response(
						JSON.stringify({
							Answer: [
								{
									name: "phish.example.com.",
									type: 1,
									TTL: 60,
									data: "203.0.113.42",
								},
							],
						}),
						{
							status: 200,
							headers: { "content-type": "application/dns-json" },
						},
					);
				}
				return null;
			},
		]);
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		const kv = makeKv();
		seedCrowdsecFeed(kv);
		const harness = makeStub([
			{ id: "u1", url: "https://phish.example.com/login" },
		]);
		// Deliberately no CTI key — the blocklist must work standalone on
		// deploys that don't pay for CrowdSec CTI enrichment.
		const env = makeEnv({
			kv,
			bucket: makeBucket({}),
			stub: harness.stub,
		});

		const result = await runDeepScan({
			env,
			mailboxId: "m@x",
			emailId: "e1",
		});

		const reasonsBlob = result.reasons.join(" | ");
		expect(reasonsBlob).toMatch(/redirect target IP 203\.0\.113\.42/);
		// Operator-facing label must be the human name, not the bare feed id.
		expect(reasonsBlob).toMatch(/CrowdSec Community Blocklist/);
		// IP-feed per-hit weight (+20) is included in the deep-scan delta.
		expect(result.added_score).toBeGreaterThanOrEqual(20);
		// CTI must NOT have been called — no API key configured.
		const ctiCalls = fetchMock.mock.calls.filter(
			(c) => new URL(String(c[0])).hostname === "cti.api.crowdsec.net",
		);
		expect(ctiCalls.length).toBe(0);
	});
});
