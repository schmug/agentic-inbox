import { describe, expect, it } from "vitest";
import { aggregateVerdict, DEFAULT_THRESHOLDS } from "../../workers/security/verdict";
import { DEFAULT_ATTACHMENT_POLICY } from "../../workers/security/attachments";
import type { AuthVerdict } from "../../workers/security/auth";
import { scoreClassification, type ClassificationResult } from "../../workers/security/classification";

const cleanAuth: AuthVerdict = { spf: "pass", dkim: "pass", dmarc: "pass" };
const safeClass: ClassificationResult = { label: "safe", confidence: 0.9, reasoning: "ok" };

describe("aggregateVerdict", () => {
	it("produces allow for a clean, trusted email", () => {
		const v = aggregateVerdict({
			auth: cleanAuth,
			classification: safeClass,
			urls: [],
			reputation: {
				sender: "a@b.com",
				first_seen: "2026-01-01T00:00:00Z",
				last_seen: "2026-01-01T00:00:00Z",
				message_count: 5,
				avg_score: 5,
				flagged: false,
			},
		});
		expect(v.action).toBe("allow");
		expect(v.score).toBeLessThan(DEFAULT_THRESHOLDS.tag);
	});

	it("quarantines on high-confidence phishing + DMARC fail", () => {
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
			classification: { label: "phishing", confidence: 0.95, reasoning: "fake login" },
			urls: [
				{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: false },
			],
			reputation: null,
		});
		expect(["quarantine", "block"]).toContain(v.action);
		expect(v.score).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.quarantine);
		expect(v.signals.length).toBeGreaterThan(0);
	});

	it("clamps score to [0, 100]", () => {
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
			classification: { label: "phishing", confidence: 1 , reasoning: "" },
			urls: [
				{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: true },
			],
			reputation: { sender: "x", first_seen: "", last_seen: "", message_count: 1, avg_score: 99, flagged: true },
		}, DEFAULT_THRESHOLDS);
		expect(v.score).toBeLessThanOrEqual(100);
		expect(v.score).toBeGreaterThanOrEqual(0);
	});

	it("never returns negative scores even when all signals are benign", () => {
		// A clean-auth email with no other signals gets -10 from scoreAuth;
		// the aggregate must floor that at 0.
		const v = aggregateVerdict({
			auth: cleanAuth,
			classification: safeClass,
			urls: [],
			reputation: null, // first-time sender adds +5, so this caps negative
		});
		expect(v.score).toBeGreaterThanOrEqual(0);
	});

	it("explanation surfaces the first few signals", () => {
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
			classification: { label: "phishing", confidence: 0.9, reasoning: "" },
			urls: [],
			reputation: null,
		});
		expect(v.explanation.length).toBeGreaterThan(0);
		expect(v.explanation).not.toBe("no notable signals");
	});

	it("adds +25 for a container-format attachment under the default policy", () => {
		// Baseline uses DMARC-fail so score is positive before the attachment
		// contribution — otherwise the [0,100] clamp masks the real delta.
		const failAuth: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };
		const common = { auth: failAuth, classification: safeClass, urls: [], reputation: null };
		const without = aggregateVerdict(common);
		const withIso = aggregateVerdict({
			...common,
			attachments: [{ filename: "installer.iso" }],
			attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
		});
		expect(withIso.score - without.score).toBe(25);
		expect(withIso.signals.some((s) => s.includes(".iso"))).toBe(true);
	});

	it("adds +15 for a macro-enabled Office attachment", () => {
		const failAuth: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };
		const common = { auth: failAuth, classification: safeClass, urls: [], reputation: null };
		const without = aggregateVerdict(common);
		const withDocm = aggregateVerdict({
			...common,
			attachments: [{ filename: "report.docm" }],
			attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
		});
		expect(withDocm.score - without.score).toBe(15);
	});

	it("adds no score for an ordinary PDF attachment", () => {
		const failAuth: AuthVerdict = { spf: "fail", dkim: "fail", dmarc: "fail" };
		const common = { auth: failAuth, classification: safeClass, urls: [], reputation: null };
		const without = aggregateVerdict(common);
		const withPdf = aggregateVerdict({
			...common,
			attachments: [{ filename: "invoice.pdf" }],
			attachmentPolicy: DEFAULT_ATTACHMENT_POLICY,
		});
		expect(withPdf.score).toBe(without.score);
	});

	// ── Confidence dimension (issue #105) ──────────────────────────

	it("classifier timeout → classification scorer confidence ≤ 0.3 and aggregate reflects it", () => {
		// AC3 (issue #105): an LLM timeout (`label: "unavailable"`) yields
		// scorer confidence ≤ 0.3 — the per-scorer guarantee. The aggregate
		// "reflects that" via the score-weighted average: the same email
		// with a real classifier verdict produces a meaningfully higher
		// aggregate confidence. We assert both properties.
		const timeoutResult: ClassificationResult = { label: "unavailable", confidence: 0, reasoning: "timeout" };
		expect(scoreClassification(timeoutResult).confidence).toBeLessThanOrEqual(0.3);

		const baseInputs = {
			auth: { spf: "fail" as const, dkim: "fail" as const, dmarc: "fail" as const, trusted: true },
			urls: [],
			reputation: null,
		};
		const withTimeout = aggregateVerdict({ ...baseInputs, classification: timeoutResult });
		const withRealVerdict = aggregateVerdict({
			...baseInputs,
			classification: { label: "phishing", confidence: 0.9, reasoning: "fake login" },
		});
		// The timeout case must be lower than the high-confidence case —
		// that's what "aggregate reflects the low classifier confidence"
		// means in practice.
		expect(withTimeout.confidence).toBeLessThan(withRealVerdict.confidence);
	});

	it("multi-scorer corroboration → aggregate confidence ≥ 0.85", () => {
		// AC4: trusted-authserv DMARC-fail + high-confidence phishing label +
		// homograph URL + flagged-sender reputation. Every scorer is in its
		// high-confidence band; weighted average lands well above 0.85.
		const v = aggregateVerdict({
			auth: { spf: "fail", dkim: "fail", dmarc: "fail", trusted: true },
			classification: { label: "phishing", confidence: 0.95, reasoning: "fake login" },
			urls: [
				{ url: "https://paypa1.com", hostname: "paypa1.com", is_homograph: true, is_shortener: false },
			],
			reputation: {
				sender: "x@y.com",
				first_seen: "2026-01-01T00:00:00Z",
				last_seen: "2026-01-01T00:00:00Z",
				message_count: 20,
				avg_score: 80,
				flagged: true,
			},
		});
		expect(v.confidence).toBeGreaterThanOrEqual(0.85);
		// Sanity: this is the textbook "auto-quarantine, no review needed"
		// shape from the issue's failure-mode table.
		expect(v.score).toBeGreaterThanOrEqual(DEFAULT_THRESHOLDS.quarantine);
	});

	it("confidence is in [0,1] across a spread of inputs", () => {
		const cases = [
			aggregateVerdict({ auth: cleanAuth, classification: safeClass, urls: [], reputation: null }),
			aggregateVerdict({
				auth: { spf: "fail", dkim: "fail", dmarc: "fail" },
				classification: { label: "phishing", confidence: 0.9, reasoning: "" },
				urls: [],
				reputation: null,
			}),
		];
		for (const v of cases) {
			expect(v.confidence).toBeGreaterThanOrEqual(0);
			expect(v.confidence).toBeLessThanOrEqual(1);
		}
	});

	it("score-weighted aggregation: high-magnitude scorer dominates", () => {
		// Auth contributes -10 (clean DMARC pass), confidence 0.5 (no
		// trusted-authserv-id). Classifier returns `unavailable`: score 0,
		// confidence 0.1. Urls: 0/1.0. Reputation null → first-time +5/0.3.
		// Weights: |−10|=10, 0, 0, 5. Weighted = (10*0.5 + 5*0.3) / 15 ≈
		// 0.433. Locks in the score-weighted-average rule rather than a
		// plain mean (which would be (0.5+0.1+1.0+0.3)/4 = 0.475).
		const v = aggregateVerdict({
			auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
			classification: { label: "unavailable", confidence: 0, reasoning: "timeout" },
			urls: [],
			reputation: null,
		});
		// Allow ±0.005 tolerance for the 3-decimal-place rounding.
		expect(v.confidence).toBeGreaterThan(0.42);
		expect(v.confidence).toBeLessThan(0.45);
	});

	it("zero-weight fallback: every scorer contributes 0 → plain mean of confidences", () => {
		// Auth: all-none. spf/dkim/dmarc all "none" → score 0, confidence 0.2.
		// Classifier: safe high-confidence → 0, 1.0.
		// Urls: empty → 0, 1.0.
		// Reputation: well-known sender, score 0 → 0, 0.9.
		// Sum of |scores| = 0; aggregator falls back to plain mean.
		// (0.2 + 1.0 + 1.0 + 0.9) / 4 = 0.775.
		const v = aggregateVerdict({
			auth: { spf: "none", dkim: "none", dmarc: "none" },
			classification: { label: "safe", confidence: 1, reasoning: "ok" },
			urls: [],
			reputation: {
				sender: "a@b.com",
				first_seen: "2026-01-01T00:00:00Z",
				last_seen: "2026-01-01T00:00:00Z",
				message_count: 10,
				avg_score: 0,
				flagged: false,
			},
		});
		expect(v.confidence).toBe(0.775);
	});

	it("respects custom thresholds", () => {
		const base = {
			auth: cleanAuth,
			classification: { label: "spam" as const, confidence: 0.9, reasoning: "" },
			urls: [],
			reputation: null,
		};
		const strict = aggregateVerdict(base, { tag: 5, quarantine: 10, block: 20 });
		const lenient = aggregateVerdict(base, { tag: 90, quarantine: 95, block: 99 });
		expect(strict.action).not.toBe("allow");
		expect(lenient.action).toBe("allow");
	});
});
