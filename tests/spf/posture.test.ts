// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	emptySpfPosture,
	fetchSpfPosture,
	normalizeDohTxtData,
	parseSpfRecord,
	selectSpfRecord,
	type SpfKv,
} from "../../workers/spf/posture";

describe("parseSpfRecord", () => {
	it("parses a simple `-all` record with no lookups", () => {
		const r = parseSpfRecord("v=spf1 ip4:1.2.3.4 -all");
		expect(r).toEqual({
			mechanismCount: 2,
			includes: [],
			otherLookupCount: 0,
			redirect: null,
			allQualifier: "-",
		});
	});

	it("captures the include list and counts each `a`/`mx`/`exists`", () => {
		const r = parseSpfRecord(
			"v=spf1 a mx include:_spf.example.com include:_spf.acme.net exists:%{i}.bl ~all",
		);
		expect(r?.includes).toEqual(["_spf.example.com", "_spf.acme.net"]);
		expect(r?.otherLookupCount).toBe(3); // a + mx + exists
		expect(r?.allQualifier).toBe("~");
	});

	it("captures redirect= as a single lookup", () => {
		const r = parseSpfRecord("v=spf1 redirect=_spf.example.com");
		expect(r?.redirect).toBe("_spf.example.com");
		expect(r?.includes).toEqual([]);
	});

	it("returns null when the record isn't v=spf1", () => {
		expect(parseSpfRecord("v=DMARC1; p=reject")).toBeNull();
		expect(parseSpfRecord("not even a tag list")).toBeNull();
		expect(parseSpfRecord("")).toBeNull();
	});

	it("handles missing all-qualifier (defaults to + per §4.6.2)", () => {
		const r = parseSpfRecord("v=spf1 a all");
		expect(r?.allQualifier).toBe("+");
	});

	it("ignores ip4/ip6 mechanisms for lookup count", () => {
		const r = parseSpfRecord(
			"v=spf1 ip4:1.2.3.4 ip6:2001:db8::/32 ip4:5.6.7.8 -all",
		);
		expect(r?.otherLookupCount).toBe(0);
		expect(r?.includes).toEqual([]);
	});
});

describe("selectSpfRecord", () => {
	it("picks the v=spf1 record when multiple TXT entries coexist", () => {
		const r = selectSpfRecord([
			"google-site-verification=abc",
			"v=spf1 -all",
			"v=DMARC1; p=reject",
		]);
		expect(r).toBe("v=spf1 -all");
	});

	it("returns null when no v=spf1 record present", () => {
		expect(selectSpfRecord(["v=DMARC1; p=reject"])).toBeNull();
	});
});

describe("normalizeDohTxtData", () => {
	it("concatenates multi-string TXT-record fragments without inserting whitespace", () => {
		expect(normalizeDohTxtData('"v=spf1 " "ip4:1.2.3.4 -all"')).toBe(
			"v=spf1 ip4:1.2.3.4 -all",
		);
	});
});

// ── DoH integration tests ──────────────────────────────────────────────

function fakeKv(initial: Record<string, unknown> = {}): SpfKv & {
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
			Answer: records.map((data) => ({ name: "x", type: 16, data })),
		}),
		{ status: 200, headers: { "content-type": "application/dns-json" } },
	);
}

/** Build a fetch mock that dispatches by the DoH `name=` query parameter,
 * returning the SPF TXT for each known label and an empty Answer for
 * unknown labels. Hostname-based check enforces the CodeQL invariant. */
function spfDispatcher(records: Record<string, string | null>) {
	return async (url: string) => {
		const u = new URL(url);
		expect(u.hostname).toBe("cloudflare-dns.com");
		const name = u.searchParams.get("name") ?? "";
		const rec = records[name];
		if (rec === null || rec === undefined) {
			return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
				status: 200,
			});
		}
		return dohTxtResponse([`"${rec}"`]);
	};
}

describe("fetchSpfPosture", () => {
	it("resolves a simple `-all` record with no chain lookups", async () => {
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher({ "acme.com": "v=spf1 ip4:1.2.3.4 -all" }),
		});
		expect(r.allQualifier).toBe("-");
		expect(r.mechanismCount).toBe(2);
		expect(r.includes).toBe(0);
		expect(r.totalLookups).toBe(0);
		expect(r.exceedsLimit).toBe(false);
	});

	it("counts include chains and stays under the limit", async () => {
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher({
				"acme.com":
					"v=spf1 include:_spf.google.com include:_spf.salesforce.com -all",
				"_spf.google.com": "v=spf1 ip4:35.0.0.0/8 ~all",
				"_spf.salesforce.com": "v=spf1 ip4:96.0.0.0/13 ~all",
			}),
		});
		// 2 includes (apex) + 0 transitive = 2 lookups.
		expect(r.totalLookups).toBe(2);
		expect(r.includes).toBe(2);
		expect(r.exceedsLimit).toBe(false);
	});

	it("flags exceedsLimit when transitive includes push past 10", async () => {
		// apex has 5 includes; each of those has 2 more includes = 5 + 5*2 = 15.
		const apex = `v=spf1 ${[1, 2, 3, 4, 5]
			.map((i) => `include:_l1_${i}.com`)
			.join(" ")} -all`;
		const records: Record<string, string> = { "acme.com": apex };
		for (const i of [1, 2, 3, 4, 5]) {
			records[`_l1_${i}.com`] = `v=spf1 include:_l2_${i}_a.com include:_l2_${i}_b.com -all`;
			records[`_l2_${i}_a.com`] = "v=spf1 ip4:1.2.3.4 -all";
			records[`_l2_${i}_b.com`] = "v=spf1 ip4:5.6.7.8 -all";
		}
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher(records),
		});
		expect(r.exceedsLimit).toBe(true);
		expect(r.totalLookups).toBeGreaterThan(10);
	});

	it("resolves redirect= as one lookup and follows it", async () => {
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher({
				"acme.com": "v=spf1 redirect=_spf.example.com",
				"_spf.example.com": "v=spf1 ip4:1.2.3.4 -all",
			}),
		});
		expect(r.totalLookups).toBe(1); // redirect itself is the only lookup
		expect(r.exceedsLimit).toBe(false);
	});

	it("returns the empty sentinel when no SPF record exists", async () => {
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher({ "acme.com": null }),
		});
		expect(r).toEqual(emptySpfPosture());
	});

	it("returns the empty sentinel when DoH fetch rejects", async () => {
		const fetchImpl = async () => {
			throw new Error("network");
		};
		const r = await fetchSpfPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptySpfPosture());
	});

	it("returns the empty sentinel when DoH returns malformed JSON", async () => {
		const fetchImpl = async () => new Response("<html>", { status: 200 });
		const r = await fetchSpfPosture("acme.com", { fetchImpl });
		expect(r).toEqual(emptySpfPosture());
	});

	it("treats malformed records (non-v=spf1) as empty posture", async () => {
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher({ "acme.com": "this is not an SPF record" }),
		});
		expect(r).toEqual(emptySpfPosture());
	});

	it("guards against self-include cycles (visited set)", async () => {
		// The record references itself — without the visited set we'd loop.
		const r = await fetchSpfPosture("acme.com", {
			fetchImpl: spfDispatcher({
				"acme.com": "v=spf1 include:acme.com -all",
			}),
		});
		// 1 include in the apex; the self-reference is skipped by the visited
		// guard, so totalLookups stops at 1.
		expect(r.totalLookups).toBe(1);
		expect(r.exceedsLimit).toBe(false);
	});

	it("reads from KV cache when posture is stored", async () => {
		const cached = {
			record: "v=spf1 -all",
			allQualifier: "-",
			mechanismCount: 1,
			includes: 0,
			totalLookups: 0,
			exceedsLimit: false,
		};
		const kv = fakeKv({ "spf:v1:acme.com": cached });
		let calls = 0;
		const r = await fetchSpfPosture("acme.com", {
			kv,
			fetchImpl: async () => {
				calls += 1;
				return new Response("");
			},
		});
		expect(calls).toBe(0);
		expect(r.allQualifier).toBe("-");
	});

	it("writes the resolved posture to KV", async () => {
		const kv = fakeKv();
		await fetchSpfPosture("acme.com", {
			kv,
			fetchImpl: spfDispatcher({ "acme.com": "v=spf1 -all" }),
		});
		await new Promise((r) => setTimeout(r, 0));
		expect(kv.store.get("spf:v1:acme.com")).toBeDefined();
	});

	it("queries the apex domain (not a sub-label)", async () => {
		let captured = "";
		await fetchSpfPosture("acme.com", {
			fetchImpl: async (url: string) => {
				captured = url;
				return dohTxtResponse(['"v=spf1 -all"']);
			},
		});
		const u = new URL(captured);
		expect(u.searchParams.get("name")).toBe("acme.com");
		expect(u.searchParams.get("type")).toBe("TXT");
	});
});
