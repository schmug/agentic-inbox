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
import { scoreAuth } from "./auth";
import { scoreClassification } from "./classification";
import { scoreUrls } from "./urls";
import { scoreReputation } from "./reputation";
import { scoreOffHours } from "./time-rules";
import type { BusinessHours } from "./settings";
import type { AttachmentLike, AttachmentPolicy } from "./attachments";
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
	triage?: "hard_allow" | "hard_block" | "attachment_block" | "folder_bypass";
}

export interface VerdictInputs {
	auth: AuthVerdict;
	classification: ClassificationResult;
	urls: ExtractedUrl[];
	reputation: SenderReputation | null;
	/** When the mail was received. Defaults to `new Date()` if omitted. */
	receiveDate?: Date;
	/** Business-hours policy, or null when the mailbox has none configured. */
	businessHours?: BusinessHours | null;
	/** PostalMime-parsed attachments (filename/mimetype) — only metadata is needed. */
	attachments?: AttachmentLike[];
	/** Attachment-type gate policy. Pass null/undefined to skip scoring contribution. */
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

	// Off-hours scrutiny: small nudge for mail arriving outside the mailbox's
	// business hours, amplified when the classifier already flagged BEC/phishing.
	// See `time-rules.ts` for the rationale and hand trace.
	const offHours = scoreOffHours(
		inputs.receiveDate ?? new Date(),
		inputs.businessHours ?? undefined,
		inputs.classification,
		{ flaggedSender: inputs.reputation?.flagged === true },
	);
	score += offHours.score;
	signals.push(...offHours.reasons);

	// Attachment-type gate. Hard-blocks are handled by the triage tier before
	// we ever get here; in the aggregate path we only pick up the "score"
	// action contributions (container / macro-office). If a hard-block
	// attachment slipped through (policy set to "score" for executables), its
	// contribution still lands here.
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
