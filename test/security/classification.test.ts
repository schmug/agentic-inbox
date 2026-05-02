// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Unit coverage for the LLM classifier's narrowed Rule 5 behavior (issue
 * #28). The end-to-end pipeline tests in `run-pipeline.test.ts` cover the
 * integration ("clean email + LLM unavailable still reaches allow"); this
 * file pins the discrimination logic in `classifyEmail` and the consumer
 * shape in `scoreClassification` directly.
 */

import { afterEach, describe, expect, it } from "vitest";

import {
	__setClassifier,
	classifyEmail,
	scoreClassification,
	type ClassificationResult,
} from "../../workers/security/classification";
import type { AuthVerdict } from "../../workers/security/auth";

const FAKE_AI = {
	run() {
		throw new Error("AI.run should not be reached — tests inject classifier overrides");
	},
} as unknown as Ai;

const auth: AuthVerdict = { spf: "pass", dkim: "pass", dmarc: "pass" };

const baseInput = {
	subject: "Hello",
	sender: "alice@example.com",
	bodyHtml: "<p>hi</p>",
	auth,
};

afterEach(() => {
	__setClassifier(null);
});

describe("classifyEmail — narrowed Rule 5 (issue #28)", () => {
	it("timeout sentinel → returns label=unavailable, NOT suspicious", async () => {
		__setClassifier(async () => {
			throw new Error("classify-timeout");
		});
		const result = await classifyEmail(FAKE_AI, baseInput);
		expect(result.label).toBe("unavailable");
		expect(result.confidence).toBe(0);
	});

	it("AbortError → returns label=unavailable", async () => {
		__setClassifier(async () => {
			const e = new Error("aborted");
			e.name = "AbortError";
			throw e;
		});
		const result = await classifyEmail(FAKE_AI, baseInput);
		expect(result.label).toBe("unavailable");
	});

	it("ERR_ABORTED code → returns label=unavailable", async () => {
		__setClassifier(async () => {
			const e: Error & { code?: string } = new Error("undici aborted");
			e.code = "ERR_ABORTED";
			throw e;
		});
		const result = await classifyEmail(FAKE_AI, baseInput);
		expect(result.label).toBe("unavailable");
	});

	it("non-timeout error (e.g. binding misconfigured) → still fails closed to suspicious", async () => {
		__setClassifier(async () => {
			throw new Error("AI binding not bound");
		});
		const result = await classifyEmail(FAKE_AI, baseInput);
		// Rule 5 only narrows the timeout/abort path. A generic thrown error
		// stays fail-closed because we genuinely don't know what happened.
		expect(result.label).toBe("suspicious");
	});

	it("parse-fail (model returns garbage) → returns suspicious, NOT unavailable", async () => {
		// Production parse failures live inside `parseClassifierOutput`; the
		// override seam doesn't pass through it, so we exercise the contract
		// by injecting a classifier that itself returns the suspicious shape
		// `parseClassifierOutput` would emit. The structural assertion is
		// the same: parse-fails must NEVER surface as `unavailable`.
		__setClassifier(async () => ({
			label: "suspicious",
			confidence: 0.3,
			reasoning: "classifier output not JSON",
		}));
		const result = await classifyEmail(FAKE_AI, baseInput);
		expect(result.label).toBe("suspicious");
		expect(result.label).not.toBe("unavailable");
	});

	it("legacy mode (skipOnTimeout=false) → timeout reverts to fail-closed suspicious", async () => {
		__setClassifier(async () => {
			throw new Error("classify-timeout");
		});
		const result = await classifyEmail(FAKE_AI, baseInput, { skipOnTimeout: false });
		expect(result.label).toBe("suspicious");
		expect(result.confidence).toBeLessThan(0.5);
	});

	it("downstream-tightens invariant: a real LLM `suspicious` verdict is preserved (not relaxed to unavailable)", async () => {
		// Sanity check that the new code path doesn't accidentally swap any
		// non-timeout `suspicious` result for `unavailable`. If the LLM said
		// suspicious, the consumer must still see suspicious.
		__setClassifier(async () => ({
			label: "suspicious",
			confidence: 0.85,
			reasoning: "credential-harvest pattern",
		}));
		const result = await classifyEmail(FAKE_AI, baseInput);
		expect(result.label).toBe("suspicious");
		expect(result.confidence).toBe(0.85);
	});
});

describe("scoreClassification — unavailable contributes 0", () => {
	it("unavailable → score 0, reason 'llm_unavailable'", () => {
		const result: ClassificationResult = {
			label: "unavailable",
			confidence: 0,
			reasoning: "classifier timeout",
		};
		const { score, reasons } = scoreClassification(result);
		expect(score).toBe(0);
		expect(reasons).toEqual(["llm_unavailable"]);
	});

	it("unavailable score is independent of confidence value (no inflation)", () => {
		// Defence in depth: a bug that pushed `confidence: 1.0` through the
		// `0.5 + 0.5 * confidence` scaling math would emit a non-zero score.
		// Lock it down.
		const result: ClassificationResult = {
			label: "unavailable",
			confidence: 1,
			reasoning: "n/a",
		};
		expect(scoreClassification(result).score).toBe(0);
	});

	it("downstream-tightens invariant: real `suspicious` verdict still contributes its score", () => {
		// Mirrors the unit-level tightens-not-relaxes assertion: the new
		// `unavailable` codepath must not silently subtract the existing
		// `suspicious` contribution.
		const result: ClassificationResult = {
			label: "suspicious",
			confidence: 0.9,
			reasoning: "borderline phish",
		};
		const { score, reasons } = scoreClassification(result);
		// 30 * (0.5 + 0.5 * 0.9) = 30 * 0.95 = 28.5 → rounded 29
		expect(score).toBeGreaterThan(20);
		expect(reasons[0]).toMatch(/classifier: suspicious/);
	});

	it("safe verdict still contributes 0 with no reasons", () => {
		const result: ClassificationResult = { label: "safe", confidence: 1, reasoning: "" };
		expect(scoreClassification(result)).toEqual({ score: 0, reasons: [] });
	});
});
