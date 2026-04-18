// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Mailbox-level security settings, stored inline in `mailboxes/{id}.json`.
 *
 * Read-only helper — writes go through the existing mailbox settings route.
 * New fields are optional so older mailbox JSON files load cleanly.
 */

import type { Env } from "../types";
import { DEFAULT_THRESHOLDS, type VerdictThresholds } from "./verdict";
import { DEFAULT_ATTACHMENT_POLICY, type AttachmentPolicy } from "./attachments";

/**
 * Business-hours definition for the off-hours scrutiny tier.
 *
 * This is a *scoring* input — it tilts marginal verdicts, never decides them
 * alone. See `workers/security/time-rules.ts` for the rationale (BEC / wire
 * fraud is correlated with off-hours delivery). The short-circuit triage
 * layer is intentionally NOT wired to this signal: a trusted allowlisted
 * sender emailing at 3 AM is still a legitimate email.
 */
export interface BusinessHours {
	/** IANA timezone, e.g. `America/New_York`. Invalid values fall back to no contribution. */
	timezone: string;
	/** Inclusive start hour in 24h local time. 7 means 07:00 counts as in-hours. */
	start_hour: number;
	/** Exclusive end hour in 24h local time. 19 means 19:00 counts as out-of-hours. */
	end_hour: number;
	/** When true, Saturday and Sunday count as outside business hours regardless of the hour. */
	weekdays_only: boolean;
	/** Master switch so existing mailboxes opt-in explicitly. Defaults to false. */
	boost_on_off_hours: boolean;
}

export interface MailboxSecuritySettings {
	enabled: boolean;
	thresholds: VerdictThresholds;
	/** Learning mode: tag only, never auto-quarantine. */
	learning_mode: boolean;
	/** Exact sender addresses (lowercased) that short-circuit to allow when DMARC passes. */
	allowlist_senders: string[];
	/** Registrable domains (lowercased) that short-circuit to allow when DMARC passes. */
	allowlist_domains: string[];
	/** Enable the hard-allow triage tier. Requires DMARC pass — never allowlist alone. */
	trusted_auto_allow: boolean;
	/**
	 * History-based hard-allow: if a sender has ≥ this many prior messages
	 * with avg_score < 20 (and DMARC passes), auto-allow without running the
	 * classifier. Set to 0 to disable history-based hard-allow.
	 */
	trusted_auto_allow_min_messages: number;
	/** Enable the hard-block triage tier on confirmed intel-feed hits or flagged senders. */
	intel_auto_block: boolean;
	/**
	 * Optional per-mailbox business-hours policy. When present and
	 * `boost_on_off_hours` is true, mail received outside the configured window
	 * gets a small verdict-score boost. See `time-rules.ts`.
	 */
	business_hours?: BusinessHours;
	/**
	 * Per-folder pipeline policy, keyed by folder id (see shared/folders.ts).
	 *
	 * `mode` controls how much of the security pipeline runs when a message
	 * is delivered into that folder:
	 *   - "full"            — default; run the full pipeline including the LLM classifier.
	 *   - "skip_classifier" — run cheap signals + triage, but skip the LLM call.
	 *                         Aggregate scoring treats classification as "safe".
	 *   - "skip_all"        — no pipeline at all; record a synthetic allow verdict
	 *                         tagged `triage: "folder_bypass"`.
	 *
	 * `treat_as_verified` is orthogonal to `mode`: when a user moves a
	 * message into the folder, bump the sender's reputation with a score
	 * of 0 (favourable signal). The bump is idempotent against the folder
	 * transition — moving out of and back into a verified folder does not
	 * double-count (see the `/emails/:id/move` handler in workers/index.ts).
	 *
	 * Folder policies are latency/cost optimisations plus a manual trust
	 * signal. `skip_all` on INBOX is equivalent to disabling the pipeline
	 * entirely for this mailbox, which is safe only because the mailbox
	 * owner is the only actor who can configure policies. The hard-allow
	 * DMARC invariant in triage.ts is unaffected — folder-bypass is a
	 * separate, earlier tier.
	 */
	folder_policies?: Record<string, {
		mode: "full" | "skip_classifier" | "skip_all";
		treat_as_verified?: boolean;
	}>;
	/**
	 * Attachment-type gate policy. Cheap triage tier that inspects attachment
	 * metadata (filename/mimetype parsed by PostalMime) and either blocks the
	 * message outright or boosts its verdict score. Runs BEFORE the LLM
	 * classifier so we avoid the expensive stage for obvious-malicious carriers.
	 *
	 * The defaults are conservative-but-actionable: executables are hard-blocked
	 * (effectively zero legit use), containers/macros only score (legit uses
	 * exist). See `workers/security/attachments.ts` for full rules.
	 */
	attachment_policy: AttachmentPolicy;
}

export const DEFAULT_SECURITY_SETTINGS: MailboxSecuritySettings = {
	enabled: false, // opt-in — existing mailboxes are unaffected until the user flips this
	thresholds: DEFAULT_THRESHOLDS,
	learning_mode: false,
	allowlist_senders: [],
	allowlist_domains: [],
	trusted_auto_allow: true,
	trusted_auto_allow_min_messages: 10,
	intel_auto_block: true,
	attachment_policy: DEFAULT_ATTACHMENT_POLICY,
};

export async function getSecuritySettings(
	env: Env,
	mailboxId: string,
): Promise<MailboxSecuritySettings> {
	try {
		const obj = await env.BUCKET.get(`mailboxes/${mailboxId}.json`);
		if (!obj) return DEFAULT_SECURITY_SETTINGS;
		const json = (await obj.json()) as { security?: Partial<MailboxSecuritySettings> } | null;
		const raw = json?.security ?? {};
		const merged: MailboxSecuritySettings = {
			...DEFAULT_SECURITY_SETTINGS,
			...raw,
			thresholds: { ...DEFAULT_THRESHOLDS, ...(raw.thresholds ?? {}) },
			// Defensive normalisation: everything in allowlists is lowercased so
			// comparisons at runtime don't need to repeat the case fold.
			allowlist_senders: (raw.allowlist_senders ?? DEFAULT_SECURITY_SETTINGS.allowlist_senders).map((s) => s.toLowerCase()),
			allowlist_domains: (raw.allowlist_domains ?? DEFAULT_SECURITY_SETTINGS.allowlist_domains).map((s) => s.toLowerCase()),
			// business_hours: only materialise if the user supplied at least a timezone.
			// `boost_on_off_hours` defaults to false so a partially specified block is inert.
			business_hours: raw.business_hours && raw.business_hours.timezone
				? {
					timezone: raw.business_hours.timezone,
					start_hour: raw.business_hours.start_hour ?? 7,
					end_hour: raw.business_hours.end_hour ?? 19,
					weekdays_only: raw.business_hours.weekdays_only ?? true,
					boost_on_off_hours: raw.business_hours.boost_on_off_hours ?? false,
				}
				: undefined,
			// Merge attachment policy field-by-field so a partially specified user
			// block (e.g. only custom_blocklist_extensions) doesn't silently drop
			// the default actions back to "ignore" across the board.
			attachment_policy: {
				...DEFAULT_ATTACHMENT_POLICY,
				...(raw.attachment_policy ?? {}),
				custom_blocklist_extensions: (raw.attachment_policy?.custom_blocklist_extensions
					?? DEFAULT_ATTACHMENT_POLICY.custom_blocklist_extensions)
					.map((e) => e.trim().toLowerCase().replace(/^\./, ""))
					.filter((e) => e.length > 0),
			},
		};
		return merged;
	} catch (e) {
		console.error("getSecuritySettings failed:", (e as Error).message);
		return DEFAULT_SECURITY_SETTINGS;
	}
}
