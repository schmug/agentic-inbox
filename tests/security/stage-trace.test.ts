// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit tests for `parseStageTrace` — the safe-by-default JSON reader on
 * the case-detail API path. The case-detail timeline UI hides the card
 * when this returns null, so the contract is: anything malformed
 * (non-string input, broken JSON, non-array, missing keys, unknown
 * stage/status enum) collapses to null. Valid input round-trips
 * unchanged with optional `reason` preserved when present.
 */

import { describe, expect, it } from "vitest";

import { parseStageTrace, type StageRecord } from "../../workers/security/stage-trace";

describe("parseStageTrace", () => {
	const sample: StageRecord[] = [
		{ stage: "auth", status: "ok", score_contrib: 0, duration_ms: 1, reason: "DMARC pass" },
		{ stage: "url", status: "ok", score_contrib: 12, duration_ms: 2 },
		{ stage: "reputation", status: "ok", score_contrib: 5, duration_ms: 3 },
		{ stage: "intel", status: "ok", score_contrib: 0, duration_ms: 1 },
		{ stage: "triage", status: "ok", score_contrib: 0, duration_ms: 0 },
		{ stage: "llm", status: "ok", score_contrib: 35, duration_ms: 1850 },
		{ stage: "verdict", status: "ok", score_contrib: 52, duration_ms: 1 },
	];

	it("round-trips a valid trace, preserving optional reason fields", () => {
		const out = parseStageTrace(JSON.stringify(sample));
		expect(out).toEqual(sample);
	});

	it("returns null for null/undefined/empty inputs", () => {
		expect(parseStageTrace(null)).toBeNull();
		expect(parseStageTrace(undefined)).toBeNull();
		expect(parseStageTrace("")).toBeNull();
	});

	it("returns null for non-string inputs (defence against schema drift)", () => {
		expect(parseStageTrace(42)).toBeNull();
		expect(parseStageTrace(sample)).toBeNull();
		expect(parseStageTrace({ stage: "auth" })).toBeNull();
	});

	it("returns null for malformed JSON", () => {
		expect(parseStageTrace("not json")).toBeNull();
		expect(parseStageTrace("{")).toBeNull();
	});

	it("returns null when the parsed value is not an array", () => {
		expect(parseStageTrace(JSON.stringify({ stages: sample }))).toBeNull();
		expect(parseStageTrace(JSON.stringify("string"))).toBeNull();
	});

	it("returns null when an item is missing a required key", () => {
		const broken = sample.map((r) => ({ ...r }));
		// remove `score_contrib` from the first row
		delete (broken[0] as { score_contrib?: number }).score_contrib;
		expect(parseStageTrace(JSON.stringify(broken))).toBeNull();
	});

	it("returns null when stage id is unknown (closed taxonomy)", () => {
		const bad = [{ ...sample[0], stage: "deep_scan" }];
		expect(parseStageTrace(JSON.stringify(bad))).toBeNull();
	});

	it("returns null when status is unknown (closed taxonomy)", () => {
		const bad = [{ ...sample[0], status: "running" }];
		expect(parseStageTrace(JSON.stringify(bad))).toBeNull();
	});

	it("drops empty-string reason fields rather than surfacing them", () => {
		const withEmpty = [{ ...sample[0], reason: "" }];
		const out = parseStageTrace(JSON.stringify(withEmpty));
		expect(out).not.toBeNull();
		expect(out![0].reason).toBeUndefined();
	});

	it("accepts a short_circuited triage row carrying the final verdict score", () => {
		const shortCircuit: StageRecord[] = [
			{ stage: "auth", status: "ok", score_contrib: 0, duration_ms: 1 },
			{ stage: "url", status: "ok", score_contrib: 0, duration_ms: 1 },
			{ stage: "reputation", status: "ok", score_contrib: 0, duration_ms: 0 },
			{ stage: "intel", status: "ok", score_contrib: 20, duration_ms: 1 },
			{
				stage: "triage",
				status: "short_circuited",
				score_contrib: 95,
				duration_ms: 1,
				reason: "hard_block: confirmed-intel match",
			},
			{ stage: "llm", status: "skipped", score_contrib: 0, duration_ms: 0 },
			{ stage: "verdict", status: "ok", score_contrib: 95, duration_ms: 0 },
		];
		const out = parseStageTrace(JSON.stringify(shortCircuit));
		expect(out).toEqual(shortCircuit);
	});
});
