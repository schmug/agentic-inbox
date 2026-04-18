// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Layered short-circuit triage. Evaluated BEFORE the LLM classifier so we
 * can skip the expensive stage for obvious-safe or obvious-malicious mail.
 *
 * Two tiers:
 *   1. Hard block — confirmed intel-feed match OR explicitly flagged sender.
 *      Quarantines immediately; classifier never runs.
 *   2. Hard allow — DMARC pass AND (explicit allowlist OR trusted history).
 *      Returns allow immediately; classifier never runs.
 *
 * Hard-block wins over hard-allow: if someone compromises a trusted sender
 * and sends a URL we already know is malicious, we'd rather quarantine.
 *
 * IMPORTANT INVARIANT: hard-allow REQUIRES DMARC pass. Allowlist alone is
 * never sufficient — that would let anyone spoof the From address of a
 * trusted domain. DMARC pass is the bind between the From header and the
 * actual sending infrastructure.
 */

import type { AuthVerdict } from "./auth";
import type { SenderReputation } from "./reputation";
import type { ClassificationResult } from "./classification";
import type { ExtractedUrl } from "./urls";
import type { FinalVerdict, VerdictThresholds } from "./verdict";
import type { MailboxSecuritySettings } from "./settings";

export interface IntelMatchInfo {
	matched: true;
	feedId: string;
	value: string;
	confirmed: boolean;
}

export interface TriageInputs {
	sender: string;
	auth: AuthVerdict;
	reputation: SenderReputation | null;
	urls: ExtractedUrl[];
	intelMatch: IntelMatchInfo | null;
	settings: MailboxSecuritySettings;
}

export interface TriageResult {
	verdict: FinalVerdict;
	tier: "hard_block" | "hard_allow";
	reason: string;
}

const SKIP_CLASSIFICATION: ClassificationResult = {
	label: "safe",
	confidence: 1.0,
	reasoning: "classifier skipped by triage",
};

export function evaluateTriage(inputs: TriageInputs): TriageResult | null {
	const { settings } = inputs;

	// Tier 1: hard block — runs first so a compromised-but-allowlisted
	// sender who's sending a known-bad URL still gets stopped.
	if (settings.intel_auto_block) {
		const block = evaluateHardBlock(inputs);
		if (block) return block;
	}

	// Tier 2: hard allow — requires DMARC pass in ALL paths. See invariant above.
	if (settings.trusted_auto_allow) {
		const allow = evaluateHardAllow(inputs);
		if (allow) return allow;
	}

	return null;
}

function evaluateHardBlock(inputs: TriageInputs): TriageResult | null {
	const reasons: string[] = [];

	if (inputs.reputation?.flagged) {
		reasons.push(`sender flagged (${inputs.sender})`);
	}
	if (inputs.intelMatch?.confirmed) {
		reasons.push(`confirmed intel hit (${inputs.intelMatch.feedId}: ${inputs.intelMatch.value})`);
	}

	if (reasons.length === 0) return null;

	const verdict: FinalVerdict = {
		action: "quarantine",
		score: 100,
		explanation: reasons.join("; "),
		auth: inputs.auth,
		classification: { ...SKIP_CLASSIFICATION, label: "phishing", reasoning: "classifier skipped by hard-block triage" },
		signals: reasons,
	};
	return { verdict, tier: "hard_block", reason: reasons.join("; ") };
}

function evaluateHardAllow(inputs: TriageInputs): TriageResult | null {
	// CRITICAL INVARIANT: require DMARC pass. Without it, anyone can spoof
	// the From: address of a trusted domain.
	if (inputs.auth.dmarc !== "pass") return null;

	const senderMatch = inputs.settings.allowlist_senders.includes(inputs.sender);
	const domain = inputs.sender.split("@")[1] ?? "";
	const domainMatch = domain.length > 0 &&
		(inputs.settings.allowlist_domains.includes(domain) ||
			inputs.settings.allowlist_domains.some((d) => domain.endsWith("." + d)));

	const reasons: string[] = [];
	if (senderMatch) reasons.push(`sender on allowlist (${inputs.sender})`);
	else if (domainMatch) reasons.push(`domain on allowlist (${domain})`);
	else {
		// History-based hard-allow: long-standing trusted sender.
		const minMsgs = inputs.settings.trusted_auto_allow_min_messages;
		const rep = inputs.reputation;
		if (
			minMsgs > 0 &&
			rep &&
			!rep.flagged &&
			rep.message_count >= minMsgs &&
			rep.avg_score < 20
		) {
			reasons.push(`trusted history (${rep.message_count} msgs, avg ${rep.avg_score.toFixed(0)})`);
		} else {
			return null;
		}
	}
	reasons.push("DMARC pass");

	const verdict: FinalVerdict = {
		action: "allow",
		score: 0,
		explanation: reasons.join("; "),
		auth: inputs.auth,
		classification: SKIP_CLASSIFICATION,
		signals: reasons,
	};
	return { verdict, tier: "hard_allow", reason: reasons.join("; ") };
}
