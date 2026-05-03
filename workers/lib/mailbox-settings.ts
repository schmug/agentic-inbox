// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import {
	DEFAULT_AGENT_MODEL,
	DEFAULT_AUTO_DRAFT_ENABLED,
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_DRAFT_VERIFIER_MODEL,
	DEFAULT_INJECTION_SCANNER_MODEL,
	MailboxSettings,
} from "../../shared/mailbox-settings";
import type { OrgSettings } from "../../shared/org-settings";
import { getOrgSettings } from "./org-settings";
import {
	DEFAULT_SECURITY_SETTINGS,
	type MailboxSecuritySettings,
} from "../security/defaults";

type R2BucketEnv = { BUCKET: R2Bucket };

/**
 * Read the per-mailbox settings blob from R2 and parse through the Zod
 * schema. Returns an empty object (not defaults) when the blob is missing
 * or unreadable — never throws.
 *
 * After #106, this returns the *raw* mailbox JSON only. Callers that need
 * inheritance-aware values must call {@link resolveMailboxSettings}; the
 * raw helper exists for the GET /api/v1/mailboxes/:id endpoint that
 * surfaces the override-only state to the UI.
 */
export async function getMailboxSettings(
	env: R2BucketEnv,
	mailboxId: string,
): Promise<MailboxSettings> {
	try {
		const obj = await env.BUCKET.get(`mailboxes/${mailboxId}.json`);
		if (obj) {
			const raw = await obj.json<Record<string, unknown>>();
			return MailboxSettings.parse(raw);
		}
	} catch {
		// Fall through to empty — missing/malformed blob shouldn't break
		// downstream consumers. The resolver fills in defaults.
	}
	return MailboxSettings.parse({});
}

/**
 * System defaults applied as the bottom of the resolution stack. Lives
 * here (not on the Zod schema) so reads don't materialise defaults into
 * stored mailbox JSON — that distinction is what makes
 * "absent-key = inherit" possible. If any of these were on the schema,
 * the round-trip would be: read fills in default → write strips default →
 * next read fills it back in, indistinguishable from an explicit override.
 */
export const DEFAULT_MAILBOX_SETTINGS = {
	agentSystemPrompt: undefined as string | undefined,
	agentModel: DEFAULT_AGENT_MODEL,
	autoDraft: { enabled: DEFAULT_AUTO_DRAFT_ENABLED },
	injectionScannerModel: DEFAULT_INJECTION_SCANNER_MODEL,
	draftVerifierModel: DEFAULT_DRAFT_VERIFIER_MODEL,
	classifierModel: DEFAULT_CLASSIFIER_MODEL,
	security: DEFAULT_SECURITY_SETTINGS,
	intel: {} as { hub?: NonNullable<OrgSettings["intel"]>["hub"]; feeds?: NonNullable<OrgSettings["intel"]>["feeds"] },
} as const;

/**
 * Inheritance-resolved view of a mailbox's settings.
 *
 * Each field has been resolved through `mailbox > org > system default`.
 * Fields that have a system default are guaranteed-present (e.g.
 * `agentModel: string`, not `string | undefined`). Fields with no
 * meaningful default (`agentSystemPrompt`) stay `string | undefined`.
 *
 * `intel.hub` and `intel.feeds` may be `undefined` when neither tier set
 * them — there's no system default for either.
 *
 * `raw` carries the per-mailbox JSON as-stored, so callers needing strictly
 * per-mailbox fields (`fromName`, `signature`, `forwarding`, `autoReply`)
 * can reach them without a second R2 read.
 */
export interface ResolvedMailboxSettings {
	agentSystemPrompt: string | undefined;
	agentModel: string;
	autoDraft: { enabled: boolean };
	injectionScannerModel: string;
	draftVerifierModel: string;
	classifierModel: string;
	security: MailboxSecuritySettings;
	intel: {
		hub?: NonNullable<OrgSettings["intel"]>["hub"];
		feeds?: NonNullable<OrgSettings["intel"]>["feeds"];
	};
	raw: MailboxSettings;
	org: OrgSettings;
}

/**
 * Resolve a mailbox's effective settings through the full inheritance
 * hierarchy: `mailbox > org > system default`.
 *
 * Whole-object replacement for nested fields. If a mailbox sets `security`
 * (any sub-field), it carries the *whole* security object — the org
 * `security` block is NOT deep-merged in. Same for `intel.hub` and
 * `intel.feeds`. This matches the v1 decision in #106's audit (Q3, Q4,
 * Q6); per-array extend-merge semantics are tracked as separate follow-ups.
 *
 * `security` is post-normalised (lowercased allowlists, trimmed
 * blocklist extensions, etc.) so consumers don't repeat the case fold at
 * runtime — but the normalisation runs on whichever block won the resolve,
 * NOT field-by-field across tiers.
 */
export async function resolveMailboxSettings(
	env: R2BucketEnv,
	mailboxId: string,
): Promise<ResolvedMailboxSettings> {
	const [mailbox, org] = await Promise.all([
		getMailboxSettings(env, mailboxId),
		getOrgSettings(env),
	]);

	// Whole-object replace across tiers. Whichever tier supplied the field
	// wins outright — never deep-merged. Within the winning tier,
	// mergeSecurityWithDefault completes any unset fields with the system
	// default so consumers see a fully-populated MailboxSecuritySettings.
	const securityWinner = mailbox.security ?? org.security;
	const security = securityWinner
		? mergeSecurityWithDefault(securityWinner)
		: DEFAULT_SECURITY_SETTINGS;

	const intelRaw = (mailbox.intel ?? org.intel ?? {}) as NonNullable<MailboxSettings["intel"]>;

	return {
		agentSystemPrompt:
			mailbox.agentSystemPrompt ?? org.agentSystemPrompt ?? undefined,
		agentModel:
			mailbox.agentModel ?? org.agentModel ?? DEFAULT_MAILBOX_SETTINGS.agentModel,
		autoDraft: resolveAutoDraft(mailbox.autoDraft, org.autoDraft),
		injectionScannerModel:
			org.injectionScannerModel ?? DEFAULT_MAILBOX_SETTINGS.injectionScannerModel,
		draftVerifierModel:
			org.draftVerifierModel ?? DEFAULT_MAILBOX_SETTINGS.draftVerifierModel,
		classifierModel:
			org.classifierModel ?? DEFAULT_MAILBOX_SETTINGS.classifierModel,
		security: normalizeSecurity(security),
		intel: {
			hub: intelRaw.hub,
			feeds: intelRaw.feeds,
		},
		raw: mailbox,
		org,
	};
}

function resolveAutoDraft(
	mailbox: MailboxSettings["autoDraft"],
	org: OrgSettings["autoDraft"],
): { enabled: boolean } {
	const winner = mailbox ?? org;
	if (!winner) return { enabled: DEFAULT_AUTO_DRAFT_ENABLED };
	return { enabled: winner.enabled ?? DEFAULT_AUTO_DRAFT_ENABLED };
}

/**
 * Complete a partial security override (from either tier) with the system
 * default. The override carries whatever keys it set; missing keys fall
 * through to the default. This is NOT cross-tier deep merge — by the time
 * we reach this function, `value` is whichever single tier won the
 * whole-object replace, and we're just filling in unset keys from
 * DEFAULT_SECURITY_SETTINGS so consumers don't see undefined thresholds /
 * attachment_policy / classification.
 */
function mergeSecurityWithDefault(value: unknown): MailboxSecuritySettings {
	const partial = (value ?? {}) as Partial<MailboxSecuritySettings>;
	return {
		...DEFAULT_SECURITY_SETTINGS,
		...partial,
		thresholds: { ...DEFAULT_SECURITY_SETTINGS.thresholds, ...(partial.thresholds ?? {}) },
		attachment_policy: {
			...DEFAULT_SECURITY_SETTINGS.attachment_policy,
			...(partial.attachment_policy ?? {}),
		},
		classification: {
			...DEFAULT_SECURITY_SETTINGS.classification,
			...(partial.classification ?? {}),
		},
	};
}

/**
 * Lowercase allowlists and trusted-authserv-ids, normalise attachment
 * blocklist extensions. Runs on the *resolved* security block so consumers
 * don't repeat the case fold. Materialises `business_hours` defaults only
 * when a timezone is set (a partially-specified block is otherwise inert
 * because `boost_on_off_hours` defaults to false).
 */
function normalizeSecurity(s: MailboxSecuritySettings): MailboxSecuritySettings {
	return {
		...s,
		allowlist_senders: s.allowlist_senders.map((v) => v.toLowerCase()),
		allowlist_domains: s.allowlist_domains.map((v) => v.toLowerCase()),
		trusted_authserv_ids: s.trusted_authserv_ids.map((v) => v.toLowerCase()),
		attachment_policy: {
			...s.attachment_policy,
			custom_blocklist_extensions: (s.attachment_policy.custom_blocklist_extensions ?? [])
				.map((e) => e.trim().toLowerCase().replace(/^\./, ""))
				.filter((e) => e.length > 0),
		},
		business_hours: s.business_hours && s.business_hours.timezone
			? {
				timezone: s.business_hours.timezone,
				start_hour: s.business_hours.start_hour ?? 7,
				end_hour: s.business_hours.end_hour ?? 19,
				weekdays_only: s.business_hours.weekdays_only ?? true,
				boost_on_off_hours: s.business_hours.boost_on_off_hours ?? false,
			}
			: undefined,
	};
}

/**
 * Strip fields from a mailbox settings PUT payload that are equal to the
 * system default — prevents fresh mailboxes from silently overriding every
 * org-level field (acceptance criterion 6 from #106). Whole-object
 * equality for nested fields: if `incoming.security` deep-equals
 * `DEFAULT_SECURITY_SETTINGS`, the whole `security` key is dropped;
 * otherwise the whole object is kept (we never partially strip a nested
 * block, since the override semantics are whole-object replace).
 *
 * Does NOT mutate the input. Returns a new object containing only the
 * keys that survived stripping.
 */
export function stripDefaultEqual(
	settings: MailboxSettings,
): MailboxSettings {
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(settings)) {
		if (value === undefined) continue;
		if (isDefaultEqual(key, value)) continue;
		out[key] = value;
	}
	return out as MailboxSettings;
}

function isDefaultEqual(key: string, value: unknown): boolean {
	switch (key) {
		case "agentModel":
			return value === DEFAULT_MAILBOX_SETTINGS.agentModel;
		case "autoDraft":
			return deepEqual(value, DEFAULT_MAILBOX_SETTINGS.autoDraft);
		case "agentSystemPrompt":
			return value === undefined || value === "";
		case "security":
			return deepEqual(value, DEFAULT_SECURITY_SETTINGS);
		case "intel":
			// No default for intel — only strip when the override is an empty object.
			return deepEqual(value, {});
		default:
			return false;
	}
}

function deepEqual(a: unknown, b: unknown): boolean {
	if (a === b) return true;
	if (typeof a !== typeof b) return false;
	if (a === null || b === null) return false;
	if (typeof a !== "object") return false;
	if (Array.isArray(a)) {
		if (!Array.isArray(b) || a.length !== b.length) return false;
		return a.every((v, i) => deepEqual(v, (b as unknown[])[i]));
	}
	if (Array.isArray(b)) return false;
	const keysA = Object.keys(a as Record<string, unknown>);
	const keysB = Object.keys(b as Record<string, unknown>);
	if (keysA.length !== keysB.length) return false;
	return keysA.every((k) =>
		deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
	);
}
