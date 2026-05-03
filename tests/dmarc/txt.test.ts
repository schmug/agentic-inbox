// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptyDmarcTxtPosture,
	fetchDmarcTxtPosture,
	normalizeDohTxtData,
	parseDmarcTxt,
	selectDmarcRecord,
	type DmarcTxtKv,
} from "../../workers/dmarc/txt";

describe("parseDmarcTxt", () => {
	it("parses a fully-specified policy record", () => {
		const r = parseDmarcTxt(
			"v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:dmarc@acme.com",
		);
		expect(r).toEqual({
			p: "reject",
			sp: "quarantine",
			pct: 50,
			ruaConfigured: true,
		});
	});

	it("defaults pct to 100 when the tag is absent (RFC 7489 §6.3)", () => {
		const r = parseDmarcTxt("v=DMARC1; p=reject");
		expect(r.pct).toBe(100);
		expect(r.p).toBe("reject");
		expect(r.sp).toBeNull();
		expect(r.ruaConfigured).toBe(false);
	});

	it("returns null fields when the record isn't a v=DMARC1 policy", () => {
		expect(parseDmarcTxt("v=spf1 -all")).toEqual(emptyDmarcTxtPosture());
		expect(parseDmarcTxt("not even a tag list")).toEqual(emptyDmarcTxtPosture());
		expect(parseDmarcTxt("")).toEqual(emptyDmarcTxtPosture());
	});

	it("treats malformed pct as null (rather than NaN)", () => {
		const r = parseDmarcTxt("v=DMARC1; p=reject; pct=abc");
		expect(r.pct).toBeNull();
	});

	it("rejects pct outside [0,100]", () => {
		expect(parseDmarcTxt("v=DMARC1; p=reject; pct=150").pct).toBeNull();
		expect(parseDmarcTxt("v=DMARC1; p=reject; pct=-5").pct).toBeNull();
	});

	it("treats `rua=` (empty) as not configured", () => {
		const r = parseDmarcTxt("v=DMARC1; p=reject; rua=");
		expect(r.ruaConfigured).toBe(false);
	});

	it("is case-insensitive on tag names but not on values", () => {
		const r = parseDmarcTxt("V=DMARC1; P=reject; SP=none");
		// Tag names are normalized; values pass through unchanged.
		expect(r.p).toBe("reject");
		expect(r.sp).toBe("none");
	});

	it("ignores tags after the first occurrence (first-wins, doesn't downgrade)", () => {
		const r = parseDmarcTxt("v=DMARC1; p=reject; p=none");
		expect(r.p).toBe("reject");
	});
});

describe("selectDmarcRecord", () => {
	it("picks the v=DMARC1-prefixed record when multiple TXTs are present", () => {
		const r = selectDmarcRecord([
			"google-site-verification=abc",
			"v=DMARC1; p=reject",
			"v=spf1 -all",
		]);
		expect(r).toBe("v=DMARC1; p=reject");
	});

	it("returns null when no record starts with v=DMARC1", () => {
		expect(
			selectDmarcRecord(["v=spf1 -all", "google-site-verification=abc"]),
		).toBeNull();
	});

	it("matches case-insensitively and tolerates whitespace around v=", () => {
		expect(selectDmarcRecord(["V = DMARC1; p=reject"])).toMatch(/DMARC1/);
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments without inserting whitespace", () => {
		// RFC 7489 records use `;`-separated tags; the multi-string boundary in
		// DNS itself adds no character — operators put a `;` or trailing space
		// inside the quoted fragment when they want one.
		expect(
			normalizeDohTxtData('"v=DMARC1; p=reject;" "rua=mailto:dmarc@acme.com"'),
		).toBe("v=DMARC1; p=reject;rua=mailto:dmarc@acme.com");
	});

	it("strips surrounding quotes from a single-fragment string", () => {
		expect(normalizeDohTxtData('"v=DMARC1; p=reject"')).toBe("v=DMARC1; p=reject");
	});

	it("passes raw text through when no quoted fragments are present", () => {
		expect(normalizeDohTxtData("v=DMARC1; p=reject")).toBe("v=DMARC1; p=reject");
	});
});

// ── DoH integration tests ──────────────────────────────────────────────

function fakeKv(initial: Record<string, unknown> = {}): DmarcTxtKv & {
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

function dohTxtResponse(records: string[]): Response {
	return new Response(
		JSON.stringify({
			Status: 0,
			Answer: records.map((data) => ({ name: "_dmarc.acme.com", type: 16, data })),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

describe("fetchDmarcTxtPosture", () => {
	it("resolves a real policy record over DoH", async () => {
		const fetchImpl = async (url: string) => {
			// Hostname-based dispatch — substring matching on URLs is a CodeQL
			// `js/incomplete-url-substring-sanitization` trip wire (repo CLAUDE.md).
			expect(new URL(url).hostname).toBe("cloudflare-dns.com");
			return dohTxtResponse([
				'"v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@acme.com"',
			]);
		};
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		expect(r).toEqual({
			p: "reject",
			sp: null,
			pct: 50,
			ruaConfigured: true,
		});
	});

	it("picks the v=DMARC1 record when multiple TXT entries coexist at _dmarc", async () => {
		const fetchImpl = async () =>
			dohTxtResponse([
				'"google-site-verification=xyz"',
				'"v=DMARC1; p=quarantine"',
			]);
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		expect(r.p).toBe("quarantine");
	});

	it("returns the empty-posture sentinel when no record exists", async () => {
		const fetchImpl = async () =>
			new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyDmarcTxtPosture());
	});

	it("returns the empty-posture sentinel when DoH returns non-200", async () => {
		const fetchImpl = async () => new Response("nope", { status: 500 });
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyDmarcTxtPosture());
	});

	it("returns the empty-posture sentinel when fetch rejects", async () => {
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyDmarcTxtPosture());
	});

	it("returns the empty-posture sentinel when DoH returns non-JSON", async () => {
		const fetchImpl = async () => new Response("<html>", { status: 200 });
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptyDmarcTxtPosture());
	});

	it("queries the _dmarc.<domain> label, not the apex itself", async () => {
		let captured = "";
		const fetchImpl = async (url: string) => {
			captured = url;
			return dohTxtResponse(['"v=DMARC1; p=none"']);
		};
		await fetchDmarcTxtPosture("acme.com", { fetchImpl });
		const u = new URL(captured);
		expect(u.hostname).toBe("cloudflare-dns.com");
		expect(u.pathname).toBe("/dns-query");
		expect(u.searchParams.get("name")).toBe("_dmarc.acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});

	it("reads from KV cache when a parsed posture is already stored", async () => {
		const kv = fakeKv({
			"dmarc-txt:v1:acme.com": {
				p: "reject",
				sp: "reject",
				pct: 100,
				ruaConfigured: true,
			},
		});
		let calls = 0;
		const fetchImpl = async () => {
			calls += 1;
			return dohTxtResponse(['"v=DMARC1; p=none"']);
		};
		const r = await fetchDmarcTxtPosture("acme.com", { fetchImpl, kv });
		expect(calls).toBe(0);
		expect(r.p).toBe("reject");
	});

	it("writes the resolved posture (including null sentinels) to KV", async () => {
		const kv = fakeKv();
		const fetchImpl = async () => dohTxtResponse([]);
		await fetchDmarcTxtPosture("acme.com", { fetchImpl, kv });
		// Give the unawaited put microtask a chance to flush.
		await new Promise((r) => setTimeout(r, 0));
		const cached = kv.store.get("dmarc-txt:v1:acme.com");
		expect(cached).toBeDefined();
		expect(JSON.parse(cached!)).toEqual(emptyDmarcTxtPosture());
	});
});
