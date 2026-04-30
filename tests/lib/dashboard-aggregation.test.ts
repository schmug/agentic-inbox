// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import {
	bucketThreatPressure,
	computeP95,
	pipelineSuccessRate,
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
