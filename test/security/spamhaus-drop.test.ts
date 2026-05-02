// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Spamhaus DROP feed coverage.
 *
 * Three layers:
 *   1. Parser — `parseCidrFeedBody` must skip comment lines, blank lines,
 *      and malformed entries (warn-and-skip, never throw) while keeping
 *      well-formed CIDR/IP entries with trailing `; SBLxxx` references.
 *   2. Lookup — `checkIpAgainstFeeds` must report a hit for an IP that
 *      sits inside any DROP CIDR, and miss for an IP outside every CIDR.
 *      Boundary IPs (network address, broadcast address) must hit the
 *      same CIDR — catches mask off-by-one errors.
 *   3. Integration — `runDeepScan` with a redirect target whose A-record
 *      is in DROP must surface the new reason and contribute the IP-feed
 *      score bump.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { parseCidrFeedBody } from "../../workers/intel/feeds";
import { checkIpAgainstFeeds } from "../../workers/intel/feeds";
import { runDeepScan } from "../../workers/intel/deep-scan";
import type { Env } from "../../workers/types";

const FIXTURE_PATH = resolve(__dirname, "../fixtures/security/spamhaus-drop.txt");
const FIXTURE = readFileSync(FIXTURE_PATH, "utf8");

// ── Test KV / mailbox stub helpers ────────────────────────────────

interface FakeKv {
	store: Map<string, string>;
	get: (key: string, type?: "text" | "arrayBuffer") => Promise<string | null>;
	put: (key: string, value: string, opts?: { expirationTtl?: number }) => Promise<void>;
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
	const reasonsAccum: string[] = [];
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
	return { stub, reasonsAccum };
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

function makeFetchMock(handlers: Array<(url: string) => Response | Promise<Response> | null>) {
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
 * Materialise the DROP fixture into the fake KV under `intel:spamhaus-drop:cidrs`,
 * matching the storage shape `feeds.ts` writes during refresh.
 */
function seedDropFeed(kv: FakeKv): void {
	const cidrs = parseCidrFeedBody(FIXTURE, "spamhaus-drop");
	const serialized = JSON.stringify(
		cidrs.map((c) => ({ n: c.network, m: c.mask, p: c.prefix })),
	);
	kv.store.set("intel:spamhaus-drop:cidrs", serialized);
}

// ── Parser tests ──────────────────────────────────────────────────

describe("parseCidrFeedBody (Spamhaus DROP)", () => {
	it("skips comments, blanks, and malformed entries while keeping valid CIDRs/IPs", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		try {
			const cidrs = parseCidrFeedBody(FIXTURE, "spamhaus-drop");
			// 4 valid entries: 1.10.16.0/20, 5.45.207.0/24, 192.0.2.42 (/32), 46.183.220.0/22
			expect(cidrs.length).toBe(4);
			expect(cidrs[0]).toEqual(expect.objectContaining({ prefix: 20 }));
			expect(cidrs[1]).toEqual(expect.objectContaining({ prefix: 24 }));
			// Bare IP becomes /32
			expect(cidrs[2]).toEqual(expect.objectContaining({ prefix: 32 }));
			expect(cidrs[3]).toEqual(expect.objectContaining({ prefix: 22 }));
			// `not-a-cidr` is malformed — must be warn-and-skip, NOT throw.
			expect(warn).toHaveBeenCalled();
			expect(
				warn.mock.calls.some((c) => String(c[0]).includes("not-a-cidr")),
			).toBe(true);
		} finally {
			warn.mockRestore();
		}
	});

	it("does not throw on a feed of only comments and blank lines", () => {
		const empty = `; just a header\n;\n\n; nothing to see\n`;
		expect(() => parseCidrFeedBody(empty, "spamhaus-drop")).not.toThrow();
		expect(parseCidrFeedBody(empty, "spamhaus-drop")).toEqual([]);
	});
});

// ── Lookup tests ──────────────────────────────────────────────────

describe("checkIpAgainstFeeds (Spamhaus DROP)", () => {
	it("returns a match for an IP inside a DROP CIDR", async () => {
		const kv = makeKv();
		seedDropFeed(kv);
		const env = makeEnv({
			kv,
			bucket: makeBucket({}),
			stub: {},
		});
		// 1.10.16.0/20 covers 1.10.16.0 .. 1.10.31.255
		const match = await checkIpAgainstFeeds(env, "m@x", "1.10.20.5");
		expect(match).not.toBeNull();
		expect(match?.feedId).toBe("spamhaus-drop");
		expect(match?.cidr).toBe("1.10.16.0/20");
	});

	it("matches both the network address and the broadcast address of a CIDR", async () => {
		const kv = makeKv();
		seedDropFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		// 1.10.16.0/20 → network 1.10.16.0, broadcast 1.10.31.255
		const lo = await checkIpAgainstFeeds(env, "m@x", "1.10.16.0");
		const hi = await checkIpAgainstFeeds(env, "m@x", "1.10.31.255");
		expect(lo?.cidr).toBe("1.10.16.0/20");
		expect(hi?.cidr).toBe("1.10.16.0/20");
	});

	it("matches a /32 entry exactly", async () => {
		const kv = makeKv();
		seedDropFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		const exact = await checkIpAgainstFeeds(env, "m@x", "192.0.2.42");
		expect(exact?.cidr).toBe("192.0.2.42/32");
		// Adjacent IP is NOT in the /32 entry.
		const adjacent = await checkIpAgainstFeeds(env, "m@x", "192.0.2.43");
		expect(adjacent).toBeNull();
	});

	it("returns null for an IP outside every CIDR", async () => {
		const kv = makeKv();
		seedDropFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		// 8.8.8.8 is not in the fixture.
		const miss = await checkIpAgainstFeeds(env, "m@x", "8.8.8.8");
		expect(miss).toBeNull();
	});

	it("returns null for a malformed IP input", async () => {
		const kv = makeKv();
		seedDropFeed(kv);
		const env = makeEnv({ kv, bucket: makeBucket({}), stub: {} });
		expect(await checkIpAgainstFeeds(env, "m@x", "not-an-ip")).toBeNull();
	});
});

// ── Integration with runDeepScan ──────────────────────────────────

describe("runDeepScan + Spamhaus DROP", () => {
	let originalFetch: typeof fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});
	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.restoreAllMocks();
	});

	it("redirect target IP listed in DROP fires the new reason", async () => {
		const fetchMock = makeFetchMock([
			(url) => {
				if (new URL(url).hostname === "phish.example.com") {
					return new Response("<html><title>Login</title></html>", {
						status: 200,
						headers: { "content-type": "text/html" },
					});
				}
				return null;
			},
			// RDAP — empty response, no signal contribution.
			(url) => (new URL(url).hostname === "rdap.org" ? new Response("{}", { status: 200 }) : null),
			// DoH resolves the redirect host to an IP that sits in 1.10.16.0/20.
			(url) => {
				const parsed = new URL(url);
				if (parsed.hostname === "cloudflare-dns.com" && parsed.pathname.startsWith("/dns-query")) {
					return new Response(
						JSON.stringify({
							Answer: [{ name: "phish.example.com.", type: 1, TTL: 60, data: "1.10.20.5" }],
						}),
						{ status: 200, headers: { "content-type": "application/dns-json" } },
					);
				}
				return null;
			},
		]);
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		const kv = makeKv();
		seedDropFeed(kv);
		const harness = makeStub([{ id: "u1", url: "https://phish.example.com/login" }]);
		// No CTI key — DROP must work on its own without CrowdSec configured.
		const env = makeEnv({
			kv,
			bucket: makeBucket({}),
			stub: harness.stub,
		});

		const result = await runDeepScan({ env, mailboxId: "m@x", emailId: "e1" });

		const reasonsBlob = result.reasons.join(" | ");
		expect(reasonsBlob).toMatch(/redirect target IP 1\.10\.20\.5/);
		expect(reasonsBlob).toMatch(/Spamhaus DROP/);
		// Score bump from the IP-feed stage (+20) is included; URL-stage
		// signals (redirect host change, resolved homograph) may or may not
		// fire on this synthetic input, so we just bound below by the IP-feed
		// per-hit weight to keep the assertion stable.
		expect(result.added_score).toBeGreaterThanOrEqual(20);
		// CTI was NOT called — no API key configured.
		const ctiCalls = fetchMock.mock.calls.filter((c) =>
			new URL(String(c[0])).hostname === "cti.api.crowdsec.net",
		);
		expect(ctiCalls.length).toBe(0);
	});

	it("redirect target IP NOT in any DROP CIDR produces no IP-feed reason", async () => {
		const fetchMock = makeFetchMock([
			(url) => {
				if (new URL(url).hostname === "clean.example.com") {
					return new Response("<html><title>OK</title></html>", {
						status: 200,
						headers: { "content-type": "text/html" },
					});
				}
				return null;
			},
			(url) => (new URL(url).hostname === "rdap.org" ? new Response("{}", { status: 200 }) : null),
			(url) => {
				const parsed = new URL(url);
				if (parsed.hostname === "cloudflare-dns.com" && parsed.pathname.startsWith("/dns-query")) {
					return new Response(
						JSON.stringify({
							Answer: [{ name: "clean.example.com.", type: 1, TTL: 60, data: "8.8.8.8" }],
						}),
						{ status: 200, headers: { "content-type": "application/dns-json" } },
					);
				}
				return null;
			},
		]);
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		const kv = makeKv();
		seedDropFeed(kv);
		const harness = makeStub([{ id: "u1", url: "https://clean.example.com/" }]);
		const env = makeEnv({
			kv,
			bucket: makeBucket({}),
			stub: harness.stub,
		});

		const result = await runDeepScan({ env, mailboxId: "m@x", emailId: "e2" });

		const reasonsBlob = result.reasons.join(" | ");
		expect(reasonsBlob).not.toMatch(/Spamhaus DROP/);
		expect(reasonsBlob).not.toMatch(/redirect target IP 8\.8\.8\.8/);
	});
});
