// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Verdict aggregation — pure scoring function. No LLM call here.
 *
 * An LLM-final-judge was considered and rejected: it's opaque, adds latency
 * per email, and makes the pipeline harder to audit for an open-source
 * reference. The scoring function is deterministic given its inputs and
 * users can tune thresholds in mailbox settings.
 */

import type { AuthVerdict } from "./auth";
import type { ClassificationResult } from "./classification";
import type { ExtractedUrl } from "./urls";
import type { SenderReputation, FirstTimeSenderPrior } from "./reputation";
import type { AttachmentLike, AttachmentPolicy } from "./attachments";
import { scoreAuth } from "./auth";
import { scoreClassification } from "./classification";
import { scoreUrls } from "./urls";
import { scoreReputation } from "./reputation";
import { scoreAttachments } from "./attachments";

export type VerdictAction = "allow" | "tag" | "quarantine" | "block";

export interface FinalVerdict {
	action: VerdictAction;
	score: number;
	/**
	 * Aggregate confidence in [0,1]. Independent dimension from `score`:
	 * a high-score-low-confidence verdict (LLM timed out, only one signal
	 * fired) is fundamentally different from a high-score-high-confidence
	 * verdict (multiple corroborating signals). Computed as a score-weighted
	 * average of per-scorer confidences with `|score_i|` as the weight, so
	 * scorers that contributed more to the verdict influence overall
	 * confidence more. When the sum of weights is zero (every scorer
	 * contributed zero) we fall back to the plain mean of confidences. See
	 * {@link aggregateVerdict} and issue #105.
	 */
	confidence: number;
	explanation: string;
	auth: AuthVerdict;
	classification: ClassificationResult;
	signals: string[];
	/** If a triage tier short-circuited the pipeline, which one. */
	triage?: "hard_allow" | "hard_block" | "folder_bypass" | "attachment_block";
}

export interface VerdictInputs {
	auth: AuthVerdict;
	classification: ClassificationResult;
	urls: ExtractedUrl[];
	reputation: SenderReputation | null;
	/**
	 * PostalMime-parsed attachment metadata. Only filename/mimetype is read;
	 * the bodies already live in R2 by the time the pipeline runs.
	 */
	attachments?: AttachmentLike[];
	/**
	 * Attachment-type gate policy. When omitted or null, attachments
	 * contribute no score here. Hard-blocks are handled by the triage tier
	 * before aggregation; this hook only picks up the "score" contributions
	 * (container/macro-office under the defaults).
	 */
	attachmentPolicy?: AttachmentPolicy | null;
	/**
	 * Optional CTI-informed first-time-sender prior (issue #79). Computed in
	 * `runSecurityPipeline` from a CrowdSec CTI lookup on the originating
	 * `Received:` IP. When present and the sender has no history, replaces
	 * the legacy flat `+5` with a graduated bonus. Absent ⇒ legacy behaviour.
	 */
	firstTimeSenderPrior?: FirstTimeSenderPrior;
}

export interface VerdictThresholds {
	tag: number;        // score >= this → tag
	quarantine: number; // score >= this → quarantine
	block: number;      // score >= this → block (reserved for SMTP-layer; treated as quarantine here)
}

export const DEFAULT_THRESHOLDS: VerdictThresholds = {
	tag: 30,
	quarantine: 60,
	block: 80,
};

export function aggregateVerdict(
	inputs: VerdictInputs,
	thresholds: VerdictThresholds = DEFAULT_THRESHOLDS,
): FinalVerdict {
	const signals: string[] = [];
	let score = 0;
	// Per-scorer (score, confidence) pairs collected for the weighted-average
	// aggregation below. Each scorer pushes one entry; the attachment scorer
	// is skipped entirely when no policy/attachments are present (see below).
	const contributions: Array<{ score: number; confidence: number }> = [];

	const auth = scoreAuth(inputs.auth);
	score += auth.score;
	signals.push(...auth.reasons);
	contributions.push({ score: auth.score, confidence: auth.confidence });

	const cls = scoreClassification(inputs.classification);
	score += cls.score;
	signals.push(...cls.reasons);
	contributions.push({ score: cls.score, confidence: cls.confidence });

	const urls = scoreUrls(inputs.urls);
	score += urls.score;
	signals.push(...urls.reasons);
	contributions.push({ score: urls.score, confidence: urls.confidence });

	const rep = scoreReputation(inputs.reputation, inputs.firstTimeSenderPrior);
	score += rep.score;
	signals.push(...rep.reasons);
	contributions.push({ score: rep.score, confidence: rep.confidence });

	// Attachment-type gate. Hard-blocks are handled by the triage tier before
	// we ever reach aggregation; here we only pick up the "score" action
	// contributions (container / macro-office under the defaults). If a
	// policy set `executable_action: "score"`, its contribution also lands
	// here rather than short-circuiting.
	if (inputs.attachmentPolicy && inputs.attachments && inputs.attachments.length > 0) {
		const att = scoreAttachments(inputs.attachments, inputs.attachmentPolicy);
		score += att.score;
		signals.push(...att.reasons);
		contributions.push({ score: att.score, confidence: att.confidence });
	}

	score = Math.max(0, Math.min(100, Math.round(score)));

	let action: VerdictAction = "allow";
	if (score >= thresholds.block) action = "block";
	else if (score >= thresholds.quarantine) action = "quarantine";
	else if (score >= thresholds.tag) action = "tag";

	const explanation = signals.length > 0
		? signals.slice(0, 4).join("; ")
		: "no notable signals";

	return {
		action,
		score,
		confidence: aggregateConfidence(contributions),
		explanation,
		auth: inputs.auth,
		classification: inputs.classification,
		signals,
	};
}

/**
 * Combine per-scorer confidences into a single value in [0,1].
 *
 * v1 (issue #105): score-weighted average using `|score_i|` as the weight.
 * Scorers that drove the verdict more dominate the aggregate. The absolute
 * value matters because `scoreAuth` can contribute negative score (DMARC
 * pass = -10) — that's still a strong signal worth weighting at 10, not 0.
 *
 * Edge case: every scorer contributed exactly zero (a pristine-but-uncertain
 * email — no auth headers, no urls, classifier returned safe-with-zero).
 * Sum of weights is zero so the weighted-average is undefined; we fall back
 * to the plain mean of confidences. Result is rounded to 3 decimal places
 * so JSON-serialised verdicts don't churn on float dust.
 */
function aggregateConfidence(
	contributions: ReadonlyArray<{ score: number; confidence: number }>,
): number {
	if (contributions.length === 0) return 1;
	let weightedSum = 0;
	let weightTotal = 0;
	let plainSum = 0;
	for (const c of contributions) {
		const w = Math.abs(c.score);
		weightedSum += w * c.confidence;
		weightTotal += w;
		plainSum += c.confidence;
	}
	const raw = weightTotal > 0
		? weightedSum / weightTotal
		: plainSum / contributions.length;
	return Math.round(raw * 1000) / 1000;
}
