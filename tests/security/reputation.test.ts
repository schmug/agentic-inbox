import { describe, expect, it } from "vitest";
import {
	scoreReputation,
	firstTimeSenderPriorFromCti,
} from "../../workers/security/reputation";
import type { CtiSummary } from "../../workers/intel/crowdsec-cti";

function ctiSummary(overrides: Partial<CtiSummary> = {}): CtiSummary {
	return {
		classifications: [],
		behaviors: [],
		scores: { threat: 0, aggressiveness: 0, trust: 0 },
		reputation: "unknown",
		...overrides,
	};
}

describe("scoreReputation", () => {
	it("adds +5 suspicion for first-time senders (null reputation)", () => {
		const { score, reasons } = scoreReputation(null);
		expect(score).toBe(5);
		expect(reasons.join(" ")).toMatch(/first-time/i);
	});

	it("adds +5 suspicion when message_count is 0", () => {
		const { score } = scoreReputation({
			sender: "a@b.com",
			first_seen: "",
			last_seen: "",
			message_count: 0,
			avg_score: 0,
			flagged: false,
		});
		expect(score).toBe(5);
	});

	it("adds +15 suspicion for a previously flagged sender", () => {
		const { score, reasons } = scoreReputation({
			sender: "a@b.com",
			first_seen: "",
			last_seen: "",
			message_count: 10,
			avg_score: 50,
			flagged: true,
		});
		expect(score).toBe(15);
		expect(reasons.join(" ")).toMatch(/flagged/i);
	});

	it("returns zero for a trusted sender with long benign history", () => {
		const { score, reasons } = scoreReputation({
			sender: "a@b.com",
			first_seen: "",
			last_seen: "",
			message_count: 100,
			avg_score: 5,
			flagged: false,
		});
		expect(score).toBe(0);
		expect(reasons).toEqual([]);
	});

	it("adds suspicion (never subtracts) for a sender with consistently bad history", () => {
		// Regression: earlier versions subtracted from the score when
		// avg_score was high, which inverted the reputation signal —
		// a sender that has reliably been malicious in the past looked
		// *less* suspicious to the aggregator than an unknown sender.
		const { score } = scoreReputation({
			sender: "a@b.com",
			first_seen: "",
			last_seen: "",
			message_count: 20,
			avg_score: 80,
			flagged: false,
		});
		expect(score).toBeGreaterThanOrEqual(0);
	});

	describe("first-time-sender CTI prior", () => {
		it("uses the prior's score and reason instead of the legacy +5 when given", () => {
			const { score, reasons } = scoreReputation(null, {
				score: 20,
				reason: "first-time sender from 8.8.8.8 CTI reputation=malicious",
			});
			expect(score).toBe(20);
			expect(reasons).toEqual([
				"first-time sender from 8.8.8.8 CTI reputation=malicious",
			]);
			expect(reasons.join(" ")).not.toMatch(/^first-time sender$/);
		});

		it("falls back to +5 'first-time sender' when no prior is provided (legacy path)", () => {
			const { score, reasons } = scoreReputation(null);
			expect(score).toBe(5);
			expect(reasons).toEqual(["first-time sender"]);
		});

		it("ignores the prior when the sender has prior history", () => {
			const { score, reasons } = scoreReputation(
				{
					sender: "a@b.com",
					first_seen: "",
					last_seen: "",
					message_count: 10,
					avg_score: 5,
					flagged: false,
				},
				{ score: 20, reason: "should not appear" },
			);
			expect(score).toBe(0);
			expect(reasons).toEqual([]);
		});
	});
});

describe("firstTimeSenderPriorFromCti", () => {
	const ip = "203.0.113.7";

	it("malicious reputation → +20 with reputation reason", () => {
		const prior = firstTimeSenderPriorFromCti(ip, ctiSummary({ reputation: "malicious" }));
		expect(prior.score).toBe(20);
		expect(prior.reason).toContain("reputation=malicious");
		expect(prior.reason).toContain(ip);
	});

	it("suspicious reputation → +10", () => {
		const prior = firstTimeSenderPriorFromCti(ip, ctiSummary({ reputation: "suspicious" }));
		expect(prior.score).toBe(10);
		expect(prior.reason).toContain("reputation=suspicious");
	});

	it("classifications include 'tor' → +10 with classification reason", () => {
		const prior = firstTimeSenderPriorFromCti(
			ip,
			ctiSummary({ reputation: "unknown", classifications: ["tor"] }),
		);
		expect(prior.score).toBe(10);
		expect(prior.reason).toContain("classification=tor");
	});

	it("classifications include 'vpn:public' → +10", () => {
		const prior = firstTimeSenderPriorFromCti(
			ip,
			ctiSummary({ reputation: "unknown", classifications: ["vpn:public"] }),
		);
		expect(prior.score).toBe(10);
		expect(prior.reason).toContain("classification=vpn:public");
	});

	it("benign reputation → +1 (small floor, NOT zero)", () => {
		const prior = firstTimeSenderPriorFromCti(ip, ctiSummary({ reputation: "benign" }));
		expect(prior.score).toBe(1);
		expect(prior.reason).toContain("reputation=benign");
	});

	it("known and safe reputations also map to +1", () => {
		expect(firstTimeSenderPriorFromCti(ip, ctiSummary({ reputation: "known" })).score).toBe(1);
		expect(firstTimeSenderPriorFromCti(ip, ctiSummary({ reputation: "safe" })).score).toBe(1);
	});

	it("unknown reputation, no flagged classification → +5 (parity with legacy flat default)", () => {
		const prior = firstTimeSenderPriorFromCti(ip, ctiSummary({ reputation: "unknown" }));
		expect(prior.score).toBe(5);
		expect(prior.reason).toContain("reputation=unknown");
	});

	it("highest-magnitude single match wins — does NOT sum reputation+classification", () => {
		// Regression guard for the issue's "pick the highest single match per IP;
		// don't double-count if both `reputation === 'malicious'` AND
		// `classifications` includes `tor`" rule.
		const prior = firstTimeSenderPriorFromCti(
			ip,
			ctiSummary({ reputation: "malicious", classifications: ["tor"] }),
		);
		expect(prior.score).toBe(20);
		expect(prior.score).not.toBe(30);
		expect(prior.reason).toContain("reputation=malicious");
	});

	it("suspicious + tor still picks the larger single match (10 each → 10, with the malicious-style ordering)", () => {
		// Both candidates are +10; ties resolve by insertion order (reputation
		// first), so the reputation reason wins. The score should still be 10.
		const prior = firstTimeSenderPriorFromCti(
			ip,
			ctiSummary({ reputation: "suspicious", classifications: ["tor"] }),
		);
		expect(prior.score).toBe(10);
		expect(prior.reason).toContain("reputation=suspicious");
	});
});
