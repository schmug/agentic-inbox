// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { Badge, Input, Switch } from "@cloudflare/kumo";
import { GraphIcon } from "@phosphor-icons/react";
import type { HubConfigSettings } from "~/types";

/**
 * Per-mailbox threat-intel hub configuration UI (#97). Mirrors the backend
 * `HubConfig` shape in `workers/lib/hub-config.ts` so the same JSON
 * round-trips through R2 unchanged.
 *
 * Important: the API key itself is NEVER entered here. Operators store the
 * key with `wrangler secret put MY_HUB_KEY ...` and put the *name*
 * (`MY_HUB_KEY`) into `Worker secret name`. The worker resolves the live
 * value from `c.env` at call time, so rotating a key never requires
 * touching mailbox JSON.
 *
 * Validation rules mirror `loadHubConfig`'s requirements: a hub config is
 * "configured" only when url + org_uuid + api_key_secret_name are all
 * non-empty. If the operator leaves all three empty we treat the section
 * as unset and `intel.hub` is omitted from the saved settings entirely —
 * never persisted as `{}` (which would force `loadHubConfig` to return
 * null anyway, but pollutes the at-rest blob and makes audit harder).
 *
 * Inline validation (`errors`) is computed from the props so the parent's
 * Save handler can call `validateHubConfig(value)` to refuse a bad save.
 */

export interface HubSettingsPanelProps {
	value: HubConfigSettings | undefined;
	onChange: (next: HubConfigSettings | undefined) => void;
	errors?: HubFieldErrors;
}

export interface HubFieldErrors {
	url?: string;
	org_uuid?: string;
	api_key_secret_name?: string;
	default_sharing_group_uuid?: string;
}

/**
 * Returns inline-validation errors (or `null` for a valid / fully-empty
 * config). Exported so `routes/settings.tsx` can short-circuit Save before
 * calling the mutation. Pure — no React state.
 */
export function validateHubConfig(
	value: HubConfigSettings | undefined,
): HubFieldErrors | null {
	const cfg = value ?? {};
	const url = (cfg.url ?? "").trim();
	const org = (cfg.org_uuid ?? "").trim();
	const secret = (cfg.api_key_secret_name ?? "").trim();
	const sharing = (cfg.default_sharing_group_uuid ?? "").trim();

	const anyCoreSet = !!(url || org || secret);
	const anyOptionalSet =
		!!sharing || cfg.auto_report === true;

	const errors: HubFieldErrors = {};

	// Empty config is valid (we'll persist nothing).
	if (!anyCoreSet && !anyOptionalSet) return null;

	// Once any hub field is touched, the three core fields are mutually
	// required — that's the contract `loadHubConfig` enforces server-side.
	if (!url) errors.url = "Required when configuring the hub.";
	else if (!isValidHttpUrl(url)) errors.url = "Must be a valid http(s) URL.";

	if (!org) errors.org_uuid = "Required when configuring the hub.";
	else if (!isValidUuid(org))
		errors.org_uuid = "Must be a UUID (e.g. 11111111-2222-3333-4444-555555555555).";

	if (!secret)
		errors.api_key_secret_name =
			"Required. The name of a worker secret, not the value.";

	if (sharing && !isValidUuid(sharing))
		errors.default_sharing_group_uuid = "Must be a UUID, or leave blank.";

	return Object.keys(errors).length === 0 ? null : errors;
}

/**
 * Normalize the panel's working state for persistence. Returns `undefined`
 * when nothing should be written under `intel.hub` (every field empty / off),
 * preventing the "junk `{}` blob" failure mode the backend would treat as
 * unconfigured but pollutes the audit trail.
 */
export function normalizeHubConfig(
	value: HubConfigSettings | undefined,
): HubConfigSettings | undefined {
	const cfg = value ?? {};
	const url = (cfg.url ?? "").trim();
	const org = (cfg.org_uuid ?? "").trim();
	const secret = (cfg.api_key_secret_name ?? "").trim();
	const sharing = (cfg.default_sharing_group_uuid ?? "").trim();
	const auto = cfg.auto_report === true;

	if (!url && !org && !secret && !sharing && !auto) return undefined;

	const out: HubConfigSettings = {
		url,
		org_uuid: org,
		api_key_secret_name: secret,
	};
	if (sharing) out.default_sharing_group_uuid = sharing;
	if (auto) out.auto_report = true;
	return out;
}

export function HubSettingsPanel({
	value,
	onChange,
	errors,
}: HubSettingsPanelProps) {
	const cfg = value ?? {};
	const patch = (partial: Partial<HubConfigSettings>) =>
		onChange({ ...cfg, ...partial });

	const configured =
		!!(cfg.url ?? "").trim() &&
		!!(cfg.org_uuid ?? "").trim() &&
		!!(cfg.api_key_secret_name ?? "").trim();

	return (
		<section id="hub" className="pp-card p-5 space-y-5">
			<div className="flex items-center gap-2">
				<GraphIcon size={16} weight="duotone" className="text-ink-3" />
				<span className="text-sm font-medium text-ink">
					Threat-intel hub
				</span>
				{configured ? (
					<Badge variant="primary">Configured</Badge>
				) : (
					<Badge variant="secondary">Not configured</Badge>
				)}
			</div>

			<p className="text-xs text-ink-3 -mt-2">
				Connect this mailbox to a MISP-compatible hub to pull corroborated
				indicators and push your own confirmed phishing reports back. Leave
				every field blank to disable the hub for this mailbox.
			</p>

			<div className="space-y-4">
				<div>
					<Input
						label="Hub URL"
						placeholder="https://misp.example.org"
						value={cfg.url ?? ""}
						onChange={(e) => patch({ url: e.target.value })}
						aria-invalid={errors?.url ? true : undefined}
						aria-describedby={errors?.url ? "hub-url-error" : "hub-url-help"}
					/>
					<p id="hub-url-help" className="text-xs text-ink-3 mt-1">
						Base URL of your MISP-compatible instance.
					</p>
					{errors?.url ? (
						<p id="hub-url-error" className="text-xs text-red-500 mt-1">
							{errors.url}
						</p>
					) : null}
				</div>

				<div>
					<Input
						label="Organization UUID"
						placeholder="11111111-2222-3333-4444-555555555555"
						value={cfg.org_uuid ?? ""}
						onChange={(e) => patch({ org_uuid: e.target.value })}
						aria-invalid={errors?.org_uuid ? true : undefined}
						aria-describedby={
							errors?.org_uuid ? "hub-org-error" : "hub-org-help"
						}
					/>
					<p id="hub-org-help" className="text-xs text-ink-3 mt-1">
						Your MISP organization UUID. Required so peers can attribute
						contributions back to your org.
					</p>
					{errors?.org_uuid ? (
						<p id="hub-org-error" className="text-xs text-red-500 mt-1">
							{errors.org_uuid}
						</p>
					) : null}
				</div>

				<div>
					<Input
						label="Worker secret name"
						placeholder="HUB_API_KEY"
						value={cfg.api_key_secret_name ?? ""}
						onChange={(e) => patch({ api_key_secret_name: e.target.value })}
						aria-invalid={errors?.api_key_secret_name ? true : undefined}
						aria-describedby={
							errors?.api_key_secret_name
								? "hub-secret-error"
								: "hub-secret-help"
						}
					/>
					<p id="hub-secret-help" className="text-xs text-ink-3 mt-1">
						<strong>Name only — never the raw API key.</strong> Store the
						actual key with{" "}
						<code className="pp-mono">wrangler secret put</code> and enter
						the binding name here. The worker reads the live value at call
						time, so rotating the key never requires editing mailbox JSON.
					</p>
					{errors?.api_key_secret_name ? (
						<p id="hub-secret-error" className="text-xs text-red-500 mt-1">
							{errors.api_key_secret_name}
						</p>
					) : null}
				</div>

				<div>
					<Input
						label="Default sharing group UUID (optional)"
						placeholder="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
						value={cfg.default_sharing_group_uuid ?? ""}
						onChange={(e) =>
							patch({ default_sharing_group_uuid: e.target.value })
						}
						aria-invalid={
							errors?.default_sharing_group_uuid ? true : undefined
						}
						aria-describedby={
							errors?.default_sharing_group_uuid
								? "hub-sharing-error"
								: "hub-sharing-help"
						}
					/>
					<p id="hub-sharing-help" className="text-xs text-ink-3 mt-1">
						If set, auto-reports are scoped to this sharing group instead of
						being your-org-only.
					</p>
					{errors?.default_sharing_group_uuid ? (
						<p
							id="hub-sharing-error"
							className="text-xs text-red-500 mt-1"
						>
							{errors.default_sharing_group_uuid}
						</p>
					) : null}
				</div>

				<div>
					<Switch
						label="Auto-report confirmed phishing"
						checked={!!cfg.auto_report}
						onCheckedChange={(v) => patch({ auto_report: v })}
					/>
					<p className="text-xs text-ink-3 mt-1">
						When a case is confirmed as phishing, push the indicators to the
						hub automatically. Off by default — turn on once you trust your
						triage.
					</p>
				</div>
			</div>
		</section>
	);
}

function isValidHttpUrl(raw: string): boolean {
	try {
		const u = new URL(raw);
		return u.protocol === "http:" || u.protocol === "https:";
	} catch {
		return false;
	}
}

// RFC 4122 — accepts any version (1–5) and the nil UUID. Permissive on case
// because MISP's REST API normalises before comparison; we only block
// obviously-wrong shapes (e.g. missing dashes).
const UUID_RE =
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(raw: string): boolean {
	return UUID_RE.test(raw);
}
