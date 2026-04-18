// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Off-hours scrutiny tier — a *scoring contribution*, not a triage decision.
 *
 * Motivation: classic BEC and wire-fraud pretexting is strongly correlated
 * with mail that arrives outside the recipient's normal working hours. A
 * real CFO rarely emails at 3 AM to request a same-day wire transfer. On
 * its own the timestamp is a weak signal (plenty of legit automated mail
 * arrives at odd hours), so we keep the base contribution small (+5) and
 * add an escalation when an existing strong signal — a BEC/phishing
 * classification, or a flagged sender — is already present.
 *
 * Why a scoring contribution and not a triage tier:
 *   - Triage tiers short-circuit the pipeline with terminal decisions.
 *   - Off-hours alone must NEVER push a clean email into quarantine.
 *   - A legitimate DMARC-passing allowlisted sender at 3 AM should still
 *     short-circuit to allow — they really did send us mail, and that
 *     alone is not phishing. See the hard-allow invariant in triage.ts.
 *
 * Hand trace (kept in-sync with the verification plan):
 *   Receive date 2025-06-15T03:00:00Z, timezone "America/New_York"
 *   (EDT, UTC-4 → local 2025-06-14 23:00, weekday Sat).
 *   settings = { timezone, start_hour: 7, end_hour: 19, weekdays_only: true,
 *                boost_on_off_hours: true }.
 *   classification.label = "bec".
 *   → off-hours (23 outside [7,19) AND Saturday with weekdays_only)
 *     base +5, BEC escalation +15 → total +20.
 *   Same input with classification.label = "safe" at 12:00 local on a
 *   weekday → inHours=true → total 0, reasons=[].
 */

import type { ClassificationResult } from "./classification";
import type { BusinessHours } from "./settings";

export interface OffHoursScore {
	score: number;
	reasons: string[];
}

/**
 * Returns the score contribution for an email's receive time versus the
 * mailbox's configured business hours.
 *
 * Returns `{ score: 0, reasons: [] }` when:
 *   - no business-hours config is supplied,
 *   - `boost_on_off_hours` is false (opt-in),
 *   - the timezone string is invalid,
 *   - the email arrived inside business hours.
 */
export function scoreOffHours(
	date: Date,
	settings: BusinessHours | undefined,
	classification: ClassificationResult,
	options?: { flaggedSender?: boolean },
): OffHoursScore {
	if (!settings || !settings.boost_on_off_hours) return { score: 0, reasons: [] };

	const local = resolveLocal(date, settings.timezone);
	// Invalid IANA timezone → silently no-op so a typo in config can't break
	// the pipeline; this is a nudge, not a required signal.
	if (!local) return { score: 0, reasons: [] };

	const weekend = local.weekday === "Sat" || local.weekday === "Sun";
	const inHourRange = local.hour >= settings.start_hour && local.hour < settings.end_hour;
	const inBusinessHours = inHourRange && !(settings.weekdays_only && weekend);

	if (inBusinessHours) return { score: 0, reasons: [] };

	const reasons: string[] = [];
	let score = 5;
	// Zero-pad the hour so the reason string sorts/reads consistently regardless
	// of single- vs two-digit values.
	const hourLabel = String(local.hour).padStart(2, "0") + ":00";
	reasons.push(`received outside business hours (${hourLabel} ${settings.timezone})`);

	if (classification.label === "bec" || classification.label === "phishing") {
		score += 15;
		reasons.push(`off-hours ${classification.label.toUpperCase()} escalation`);
	}

	// A flagged sender would normally have already hard-blocked in triage, so
	// this branch is rare (e.g. flagged but intel_auto_block is disabled).
	if (options?.flaggedSender) {
		score += 10;
		reasons.push("off-hours flagged-sender escalation");
	}

	return { score, reasons };
}

interface LocalTime {
	hour: number;
	/** Three-letter abbreviation as produced by Intl: "Mon".."Sun". */
	weekday: string;
}

/**
 * Pulls the hour and weekday for `date` in `timezone` using Intl without any
 * external dependency. Returns null on invalid timezone (RangeError from
 * DateTimeFormat) so the caller can treat it as "no config".
 */
function resolveLocal(date: Date, timezone: string): LocalTime | null {
	try {
		const fmt = new Intl.DateTimeFormat("en-US", {
			timeZone: timezone,
			hour: "numeric",
			hour12: false,
			weekday: "short",
		});
		const parts = fmt.formatToParts(date);
		// `hour: "numeric"` with `hour12: false` can yield "24" at midnight in
		// some ICU builds; normalise to 0 so range checks behave.
		const rawHour = Number(parts.find((p) => p.type === "hour")?.value ?? "0");
		const hour = rawHour === 24 ? 0 : rawHour;
		const weekday = parts.find((p) => p.type === "weekday")?.value ?? "Mon";
		return { hour, weekday };
	} catch {
		return null;
	}
}
