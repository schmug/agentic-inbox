// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	aggregateOrgOverview,
	bucketThreatPressure,
	computeP95,
	pipelineSuccessRate,
	type OrgMailboxSummary,
} from "../../workers/lib/dashboard-aggregation";

const NOW = new Date("2026-04-29T12:00:00Z");

function isoHoursAgo(hours: number): string {
	return new Date(NOW.getTime() - hours * 60 * 60 * 1000).toISOString();
}

function row(date: string | null, action: string | null) {
	return {
		date,
		security_verdict: action ? JSON.stringify({ action }) : null,
	};
}

describe("bucketThreatPressure", () => {
	it("returns 12 zero buckets when no rows are supplied", () => {
		const buckets = bucketThreatPressure([], { now: NOW });
		expect(buckets).toHaveLength(12);
		expect(buckets.every((v) => v === 0)).toBe(true);
	});

	it("ignores allow verdicts and unparseable JSON", () => {
		const rows = [
			row(isoHoursAgo(1), "allow"),
			{ date: isoHoursAgo(1), security_verdict: "not-json" },
			row(isoHoursAgo(1), "block"),
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
	});

	it("counts tag/quarantine/block verdicts", () => {
		const rows = [
			row(isoHoursAgo(0.5), "tag"),
			row(isoHoursAgo(0.5), "quarantine"),
			row(isoHoursAgo(0.5), "block"),
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(3);
	});

	it("places older rows in lower-index buckets, newer rows in higher", () => {
		const rows = [
			row(isoHoursAgo(23), "block"), // oldest, bucket 0
			row(isoHoursAgo(0.5), "block"), // newest, bucket 11
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets[0]).toBe(1);
		expect(buckets[11]).toBe(1);
		expect(buckets.slice(1, 11).every((v) => v === 0)).toBe(true);
	});

	it("drops rows outside the 24h window", () => {
		const rows = [
			row(isoHoursAgo(25), "block"), // too old
			row(isoHoursAgo(-1), "block"), // future
			row(isoHoursAgo(2), "block"), // in window
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
	});

	it("drops rows with unparseable dates", () => {
		const rows = [
			row("not-a-date", "block"),
			row(null, "block"),
			row(isoHoursAgo(1), "block"),
		];
		const buckets = bucketThreatPressure(rows, { now: NOW });
		expect(buckets.reduce((a, b) => a + b, 0)).toBe(1);
	});

	it("honors a custom bucket count and window", () => {
		const rows = [row(isoHoursAgo(0.25), "block")];
		const buckets = bucketThreatPressure(rows, {
			now: NOW,
			bucketCount: 4,
			windowHours: 1,
		});
		expect(buckets).toHaveLength(4);
		expect(buckets[3]).toBe(1);
	});
});

describe("pipelineSuccessRate", () => {
	it("returns null when no runs are recorded", () => {
		expect(pipelineSuccessRate({ completed: 0, failed: 0 })).toBeNull();
	});

	it("computes the success ratio when both buckets have counts", () => {
		expect(pipelineSuccessRate({ completed: 9, failed: 1 })).toBeCloseTo(0.9);
	});

	it("returns 1 when nothing failed and 0 when everything failed", () => {
		expect(pipelineSuccessRate({ completed: 5, failed: 0 })).toBe(1);
		expect(pipelineSuccessRate({ completed: 0, failed: 3 })).toBe(0);
	});
});

function verdictRow(action: string, label: string, date = NOW.toISOString()) {
	return {
		date,
		security_verdict: JSON.stringify({
			action,
			classification: { label },
		}),
	};
}

function summary(partial: Partial<OrgMailboxSummary> = {}): OrgMailboxSummary {
	return {
		threatsBlocked: 0,
		threatsBlocked7d: 0,
		openCases: 0,
		hubContributions: 0,
		pipelineScan: { completed: 0, failed: 0 },
		verdictRows: [],
		...partial,
	};
}

describe("aggregateOrgOverview", () => {
	it("returns zeroed counters and empty verdict mix for an empty org", () => {
		const result = aggregateOrgOverview({
			mailboxes: [],
			summaries: [],
			now: NOW.toISOString(),
		});
		expect(result).toMatchObject({
			threatsBlocked24h: 0,
			threatsBlocked7d: 0,
			openCasesTotal: 0,
			hubContributions24h: 0,
			mailboxesCount: 0,
			domainsCount: 0,
			topThreats: [],
			verdictMix: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
			pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 },
		});
	});

	it("sums KPI counters across mailboxes and skips null (failed) summaries", () => {
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
				{ id: "c@y.com", email: "c@y.com" },
			],
			summaries: [
				summary({
					threatsBlocked: 2,
					threatsBlocked7d: 14,
					openCases: 3,
					hubContributions: 1,
					pipelineScan: { completed: 90, failed: 10 },
				}),
				summary({
					threatsBlocked: 1,
					threatsBlocked7d: 7,
					openCases: 2,
					hubContributions: 0,
					pipelineScan: { completed: 100, failed: 0 },
				}),
				null, // c@y.com — DO call failed
			],
			now: NOW.toISOString(),
		});
		expect(result.mailboxesCount).toBe(3);
		expect(result.domainsCount).toBe(2);
		expect(result.threatsBlocked24h).toBe(3);
		expect(result.threatsBlocked7d).toBe(21);
		expect(result.openCasesTotal).toBe(5);
		expect(result.hubContributions24h).toBe(1);
		expect(result.pipelineHealth.runs24h).toBe(200);
		expect(result.pipelineHealth.successRate24h).toBeCloseTo(0.95);
		expect(result.pipelineHealth.p95Ms).toBeNull();
	});

	it("counts verdict-mix labels across all parseable rows", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("allow", "safe"),
						verdictRow("tag", "suspicious"),
						verdictRow("quarantine", "phishing"),
						verdictRow("block", "phishing"),
						verdictRow("tag", "spam"),
						verdictRow("quarantine", "bec"),
						{ date: NOW.toISOString(), security_verdict: "not-json" },
					],
				}),
			],
			now: NOW.toISOString(),
		});
		expect(result.verdictMix).toEqual({
			safe: 1,
			suspicious: 1,
			phishing: 2,
			spam: 1,
			bec: 1,
		});
	});

	it("ranks top-threats by count and excludes safe/allow rows", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("allow", "safe"), // excluded
						verdictRow("tag", "phishing"),
						verdictRow("quarantine", "phishing"),
						verdictRow("block", "phishing"),
						verdictRow("tag", "spam"),
						verdictRow("tag", "spam"),
						verdictRow("quarantine", "bec"),
					],
				}),
			],
			topN: 5,
			now: NOW.toISOString(),
		});
		expect(result.topThreats).toEqual([
			{ category: "phishing", count: 3 },
			{ category: "spam", count: 2 },
			{ category: "bec", count: 1 },
		]);
	});

	it("dedupes domain count by lowercased domain", () => {
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@example.com", email: "a@example.com" },
				{ id: "b@Example.com", email: "b@Example.com" },
				{ id: "c@other.com", email: "c@other.com" },
				{ id: "no-domain", email: "no-domain" }, // ignored
			],
			summaries: [null, null, null, null],
			now: NOW.toISOString(),
		});
		expect(result.mailboxesCount).toBe(4);
		expect(result.domainsCount).toBe(2);
	});

	it("respects a custom topN", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [
				summary({
					verdictRows: [
						verdictRow("tag", "phishing"),
						verdictRow("tag", "spam"),
						verdictRow("tag", "bec"),
					],
				}),
			],
			topN: 2,
			now: NOW.toISOString(),
		});
		expect(result.topThreats).toHaveLength(2);
	});

	it("unions per-mailbox pipelineDurationsMs and computes an org-wide p95", () => {
		// Two mailboxes contribute 10 + 10 samples; 2 are heavy-tailed outliers.
		// Union sorted: ten 100s, eight 200s, two 9000s. n=20, rank=0.95*19=18.05
		// → interpolate between sample[18]=9000 and sample[19]=9000 → 9000.
		const result = aggregateOrgOverview({
			mailboxes: [
				{ id: "a@x.com", email: "a@x.com" },
				{ id: "b@x.com", email: "b@x.com" },
			],
			summaries: [
				summary({
					pipelineDurationsMs: [
						100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
					],
				}),
				summary({
					pipelineDurationsMs: [200, 200, 200, 200, 200, 200, 200, 200, 9000, 9000],
				}),
			],
			now: NOW.toISOString(),
		});
		expect(result.pipelineHealth.p95Ms).toBe(9000);
	});

	it("returns null p95 when no mailbox contributes durations", () => {
		const result = aggregateOrgOverview({
			mailboxes: [{ id: "m@x.com", email: "m@x.com" }],
			summaries: [summary({})], // no pipelineDurationsMs
			now: NOW.toISOString(),
		});
		expect(result.pipelineHealth.p95Ms).toBeNull();
	});
});

describe("computeP95", () => {
	it("returns null for an empty sample", () => {
		expect(computeP95([])).toBeNull();
	});

	it("returns the single value for a one-element sample", () => {
		expect(computeP95([42])).toBe(42);
	});

	it("interpolates between adjacent ranks", () => {
		// 100 values 1..100 → rank = 0.95 * 99 = 94.05 → between sample[94]=95 and sample[95]=96
		const durations = Array.from({ length: 100 }, (_, i) => i + 1);
		expect(computeP95(durations)).toBeCloseTo(95.05, 2);
	});

	it("matches the top-tier value for a heavy-tailed distribution", () => {
		// 19 small values + 1 outlier — p95 sits in the outlier region.
		const durations = [
			...Array.from({ length: 19 }, () => 100),
			5000,
		];
		// Sorted: nineteen 100s then 5000. rank = 0.95 * 19 = 18.05 →
		// interpolate between sample[18]=100 and sample[19]=5000 = 100 + 0.05*(5000-100)
		expect(computeP95(durations)).toBeCloseTo(345, 0);
	});

	it("drops negative and non-finite values rather than counting them", () => {
		// Three 100s plus garbage that should be discarded.
		const durations = [100, 100, 100, Number.NaN, Number.POSITIVE_INFINITY, -50];
		expect(computeP95(durations)).toBe(100);
	});

	it("does not require pre-sorted input", () => {
		expect(computeP95([900, 100, 500, 200, 300])).toBeCloseTo(820, 0);
	});
});
