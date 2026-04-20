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
import type { SenderReputation } from "./reputation";
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

	const auth = scoreAuth(inputs.auth);
	score += auth.score;
	signals.push(...auth.reasons);

	const cls = scoreClassification(inputs.classification);
	score += cls.score;
	signals.push(...cls.reasons);

	const urls = scoreUrls(inputs.urls);
	score += urls.score;
	signals.push(...urls.reasons);

	const rep = scoreReputation(inputs.reputation);
	score += rep.score;
	signals.push(...rep.reasons);

	// Attachment-type gate. Hard-blocks are handled by the triage tier before
	// we ever reach aggregation; here we only pick up the "score" action
	// contributions (container / macro-office under the defaults). If a
	// policy set `executable_action: "score"`, its contribution also lands
	// here rather than short-circuiting.
	if (inputs.attachmentPolicy && inputs.attachments && inputs.attachments.length > 0) {
		const att = scoreAttachments(inputs.attachments, inputs.attachmentPolicy);
		score += att.score;
		signals.push(...att.reasons);
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
		explanation,
		auth: inputs.auth,
		classification: inputs.classification,
		signals,
	};
}
