// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Per-sender reputation tracking. Stored on the mailbox DO so each mailbox
 * has its own view (senders that are trusted by one user can be new/untrusted
 * for another — correct behaviour for a personal inbox).
 */

import type { CtiSummary } from "../intel/crowdsec-cti";

export interface SenderReputation {
	sender: string;
	first_seen: string;
	last_seen: string;
	message_count: number;
	avg_score: number;
	flagged: boolean;
}

/**
 * Optional CTI-informed prior for the first-time-sender branch. When
 * provided, replaces the legacy flat `+5` with a graduated bonus computed
 * from CrowdSec CTI on the originating `Received:` IP. See
 * `firstTimeSenderPriorFromCti` for the score-map and the "highest single
 * match" rule.
 */
export interface FirstTimeSenderPrior {
	score: number;
	reason: string;
}

/**
 * Score the sender's reputation. The first-time-sender branch optionally
 * accepts a CTI-informed prior (issue #79); when absent it falls back to
 * the legacy flat `+5` so callers without a CTI client (or where CTI
 * returned null — no key, 404, 429, network error) keep the original
 * behaviour.
 */
/**
 * Confidence sources (issue #105, v1):
 *   - History-known sender → confidence ramps with `message_count`,
 *     reaching a high plateau at ~10 messages (`min(0.9, 0.3 + 0.06 *
 *     count)`). 10 messages is the same threshold as
 *     `trusted_auto_allow_min_messages` so the ramp aligns with the
 *     operator's intuition for "we know this sender".
 *   - `flagged` history → 0.95 regardless of count: an operator has
 *     explicitly marked this sender bad.
 *   - First-time sender with a CTI prior → 0.7 (we have an external
 *     signal, but only one).
 *   - First-time sender with no CTI → 0.3 (the legacy +5 is a
 *     low-information default).
 */
export function scoreReputation(
	rep: SenderReputation | null,
	prior?: FirstTimeSenderPrior,
): { score: number; reasons: string[]; confidence: number } {
	const reasons: string[] = [];
	let score = 0;
	if (!rep || rep.message_count === 0) {
		if (prior) {
			score += prior.score;
			reasons.push(prior.reason);
			return { score, reasons, confidence: 0.7 };
		}
		score += 5;
		reasons.push("first-time sender");
		return { score, reasons, confidence: 0.3 };
	}
	if (rep.flagged) { score += 15; reasons.push("sender previously flagged"); }
	// Consistently-bad history adds suspicion. The score here is a small
	// nudge rather than a hard signal — the `flagged` branch above is the
	// deliberate-action path; this catches senders whose verdicts have been
	// piling up without anyone flipping the flag.
	if (rep.avg_score > 70) {
		score += 10;
		reasons.push(`bad sender history (avg ${rep.avg_score.toFixed(0)})`);
	}
	const confidence = rep.flagged
		? 0.95
		: Math.min(0.9, 0.3 + 0.06 * rep.message_count);
	return { score, reasons, confidence };
}

/**
 * Map a CrowdSec CTI summary onto a graduated first-time-sender prior.
 *
 * The score map (issue #79):
 *
 *   - reputation `malicious`                                  → +20
 *   - reputation `suspicious`                                 → +10
 *   - classifications include `tor` or `vpn:public`           → +10
 *   - reputation `unknown`                                    → +5  (legacy)
 *   - reputation `known` / `benign` / `safe`                  → +1  (small floor)
 *
 * "Highest-magnitude single match" rule: if multiple categories fire we
 * pick the largest single bonus and surface its reason — we DO NOT sum.
 * E.g. `reputation === "malicious"` AND `classifications.includes("tor")`
 * yields +20 with the `reputation=malicious` reason, not +30.
 *
 * The IP is rendered into the reason string so reviewers can correlate the
 * verdict back to a specific `Received:` hop.
 */
export function firstTimeSenderPriorFromCti(
	ip: string,
	summary: CtiSummary,
): FirstTimeSenderPrior {
	const candidates: FirstTimeSenderPrior[] = [];

	if (summary.reputation === "malicious") {
		candidates.push({
			score: 20,
			reason: `first-time sender from ${ip} CTI reputation=malicious`,
		});
	} else if (summary.reputation === "suspicious") {
		candidates.push({
			score: 10,
			reason: `first-time sender from ${ip} CTI reputation=suspicious`,
		});
	}

	const flaggedClassification = summary.classifications.find(
		(c) => c === "tor" || c === "vpn:public",
	);
	if (flaggedClassification) {
		candidates.push({
			score: 10,
			reason: `first-time sender from ${ip} classification=${flaggedClassification}`,
		});
	}

	if (
		summary.reputation === "known" ||
		summary.reputation === "benign" ||
		summary.reputation === "safe"
	) {
		candidates.push({
			score: 1,
			reason: `first-time sender from ${ip} CTI reputation=${summary.reputation}`,
		});
	}

	if (candidates.length === 0) {
		// `unknown` reputation with no flagged classifications — treat as the
		// legacy flat +5 but tag the IP so operators see CTI was consulted.
		return {
			score: 5,
			reason: `first-time sender from ${ip} CTI reputation=unknown`,
		};
	}

	// Highest single match wins; ties resolved by insertion order (malicious /
	// suspicious before classifications before known/benign/safe).
	let winner = candidates[0];
	for (const c of candidates.slice(1)) {
		if (c.score > winner.score) winner = c;
	}
	return winner;
}
