// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptyDkimPosture,
	fetchDkimPosture,
	isAnyPublished,
	isPublishedDkimRecord,
	normalizeDohTxtData,
	type DkimPostureKv,
} from "../../workers/dkim/posture";

describe("isPublishedDkimRecord", () => {
	it("treats a canonical v=DKIM1 record with non-empty p= as published", () => {
		expect(
			isPublishedDkimRecord("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ"),
		).toBe(true);
	});

	it("treats v=DKIM1 with empty p= as 'revoked' — NOT published", () => {
		// RFC 6376 §3.6.1 — `p=` empty signals the operator has retired the
		// key. The label still resolves but the selector should be treated as
		// gone; counting it as published would mislead the dashboard into
		// claiming a retired selector is still in service.
		expect(isPublishedDkimRecord("v=DKIM1; k=rsa; p=")).toBe(false);
	});

	it("treats v=DKIM1 with no p= tag as published (forgiving toward malformed-but-shaped records)", () => {
		expect(isPublishedDkimRecord("v=DKIM1; k=rsa")).toBe(true);
	});

	it("treats a record without v=DKIM1 but with non-empty p= as published (legacy form)", () => {
		expect(isPublishedDkimRecord("k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ")).toBe(true);
	});

	it("rejects a non-DKIM TXT entry", () => {
		expect(isPublishedDkimRecord("google-site-verification=abc")).toBe(false);
		expect(isPublishedDkimRecord("v=spf1 -all")).toBe(false);
		expect(isPublishedDkimRecord("")).toBe(false);
	});

	it("is case-insensitive on tag names and on v= value", () => {
		expect(isPublishedDkimRecord("V=DKIM1; K=rsa; P=AAA")).toBe(true);
		expect(isPublishedDkimRecord("v=dkim1; p=AAA")).toBe(true);
	});
});

describe("isAnyPublished", () => {
	it("returns true when at least one TXT entry is a valid DKIM record", () => {
		expect(
			isAnyPublished([
				"google-site-verification=abc",
				"v=DKIM1; k=rsa; p=AAA",
				"some-other=tag",
			]),
		).toBe(true);
	});

	it("returns false when no TXT entry is a valid DKIM record", () => {
		expect(isAnyPublished(["v=spf1 -all", "x=y"])).toBe(false);
		expect(isAnyPublished([])).toBe(false);
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments", () => {
		expect(
			normalizeDohTxtData(
				'"v=DKIM1; k=rsa; " "p=MIGfMA0GCSqGSIb3DQEBAQ"',
			),
		).toBe("v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ");
	});

	it("strips surrounding quotes from a single-fragment string", () => {
		expect(normalizeDohTxtData('"v=DKIM1; p=AAA"')).toBe("v=DKIM1; p=AAA");
	});
});

// ── DoH integration tests ──────────────────────────────────────────────

function fakeKv(initial: Record<string, unknown> = {}): DkimPostureKv & {
	store: Map<string, string>;
} {
	const store = new Map<string, string>();
	for (const [k, v] of Object.entries(initial)) {
		store.set(k, JSON.stringify(v));
	}
	return {
		store,
		async get(key: string, _type: "json") {
			const raw = store.get(key);
			return raw ? (JSON.parse(raw) as unknown) : null;
		},
		async put(key: string, value: string) {
			store.set(key, value);
		},
	};
}

function dohTxtResponse(records: string[], status = 0): Response {
	return new Response(
		JSON.stringify({
			Status: status,
			Answer: records.map((data) => ({ type: 16, data })),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

function dohNxdomainResponse(): Response {
	// Cloudflare's resolver returns Status:3 (NXDOMAIN) with no Answer field.
	return new Response(JSON.stringify({ Status: 3 }), { status: 200 });
}

describe("fetchDkimPosture", () => {
	it("returns the empty posture for a domain with zero observed selectors (no DoH calls)", async () => {
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse([]);
		};
		const r = await fetchDkimPosture("acme.com", [], { fetchImpl });
		expect(r).toEqual(emptyDkimPosture());
		expect(calls).toBe(0);
	});

	it("resolves one selector with a passing TXT record as published=true", async () => {
		const fetchImpl = async (url: string) => {
			// Hostname-based dispatch — substring matching on URLs is a CodeQL
			// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			expect(new URL(url).searchParams.get("name")).toBe(
				"sel1._domainkey.acme.com",
			);
			return dohTxtResponse(['"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQ"']);
		};
		const r = await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel1", published: true }],
		});
	});

	it("treats NXDOMAIN as a durable published=false", async () => {
		const fetchImpl = async () => dohNxdomainResponse();
		const r = await fetchDkimPosture("acme.com", ["missing"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "missing", published: false }],
		});
	});

	it("treats NOERROR-no-data as a durable published=false", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0 }), { status: 200 });
		const r = await fetchDkimPosture("acme.com", ["empty"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "empty", published: false }],
		});
	});

	it("returns mixed published/missing posture across multiple selectors", async () => {
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name");
			if (name === "good._domainkey.acme.com") {
				return dohTxtResponse(['"v=DKIM1; k=rsa; p=AAA"']);
			}
			if (name === "gone._domainkey.acme.com") {
				return dohNxdomainResponse();
			}
			throw new Error(`unexpected DoH name: ${name}`);
		};
		const r = await fetchDkimPosture("acme.com", ["good", "gone"], {
			fetchImpl,
		});
		expect(r).toEqual({
			selectors: [
				{ selector: "gone", published: false },
				{ selector: "good", published: true },
			],
		});
	});

	it("returns published=null on DoH non-200 (transient unavailability)", async () => {
		const fetchImpl = async () => new Response("server error", { status: 500 });
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("returns published=null when DoH fetch rejects (timeout / network)", async () => {
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("returns published=null when DoH returns malformed JSON", async () => {
		const fetchImpl = async () =>
			new Response("<html>", { status: 200 });
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("treats SERVFAIL (Status=2) as a transient null, not durable false", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 2 }), { status: 200 });
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
	});

	it("counts an empty p= record as published=false (revoked key)", async () => {
		const fetchImpl = async () => dohTxtResponse(['"v=DKIM1; k=rsa; p="']);
		const r = await fetchDkimPosture("acme.com", ["retired"], { fetchImpl });
		expect(r).toEqual({
			selectors: [{ selector: "retired", published: false }],
		});
	});

	it("dedupes selector inputs case-insensitively", async () => {
		const seen: string[] = [];
		const fetchImpl = async (url: string) => {
			const name = new URL(url).searchParams.get("name") ?? "";
			seen.push(name);
			return dohTxtResponse(['"v=DKIM1; p=AAA"']);
		};
		await fetchDkimPosture("acme.com", ["Sel1", "sel1", "SEL1"], { fetchImpl });
		expect(seen).toEqual(["sel1._domainkey.acme.com"]);
	});

	it("reads from KV cache when a per-selector posture is stored", async () => {
		const kv = fakeKv({
			"dkim-published:v1:acme.com:sel1": { published: true },
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=DKIM1; p=BBB"']);
		};
		const r = await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl, kv });
		expect(calls).toBe(0);
		expect(r).toEqual({
			selectors: [{ selector: "sel1", published: true }],
		});
	});

	it("writes the durable-positive posture to KV", async () => {
		const kv = fakeKv();
		const fetchImpl = async () =>
			dohTxtResponse(['"v=DKIM1; p=AAA"']);
		await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("dkim-published:v1:acme.com:sel1");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({ published: true });
	});

	it("writes the durable-negative posture to KV (NXDOMAIN sticks for the TTL)", async () => {
		const kv = fakeKv();
		const fetchImpl = async () => dohNxdomainResponse();
		await fetchDkimPosture("acme.com", ["gone"], { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("dkim-published:v1:acme.com:gone");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual({ published: false });
	});

	it("does NOT cache the unavailable sentinel (transient errors mustn't poison the cache)", async () => {
		const kv = fakeKv();
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchDkimPosture("acme.com", ["sel"], { fetchImpl, kv });
		await new Promise((r) => setTimeout(r, 0));
		expect(r).toEqual({
			selectors: [{ selector: "sel", published: null }],
		});
		expect(kv.store.has("dkim-published:v1:acme.com:sel")).toBe(false);
	});

	it("falls through KV miss to DoH and writes the result", async () => {
		const kv = fakeKv();
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=DKIM1; p=AAA"']);
		};
		const r = await fetchDkimPosture("acme.com", ["sel1"], { fetchImpl, kv });
		expect(calls).toBe(1);
		expect(r).toEqual({
			selectors: [{ selector: "sel1", published: true }],
		});
	});

	it("queries the <selector>._domainkey.<domain> label with TXT", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			captured = url;
			return dohTxtResponse(['"v=DKIM1; p=AAA"']);
		};
		await fetchDkimPosture("acme.com", ["googleapis"], { fetchImpl });
		const u = new URL(captured);
		expect(u.hostname).toBe("cloudflare-dns.com");
		expect(u.pathname).toBe("/dns-query");
		expect(u.searchParams.get("name")).toBe("googleapis._domainkey.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});
});
