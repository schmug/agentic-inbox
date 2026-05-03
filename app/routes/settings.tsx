// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Badge, Button, Input, Loader } from "@cloudflare/kumo";
import { RobotIcon, ArrowCounterClockwiseIcon } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { useFeedback } from "~/lib/feedback";
import { useMailbox, useUpdateMailbox } from "~/queries/mailboxes";
import { useOrgSettings } from "~/queries/org-settings";
import { useTextModels } from "~/queries/text-models";
import { SecuritySettingsPanel } from "~/components/SecuritySettingsPanel";
import {
	HubSettingsPanel,
	normalizeHubConfig,
	validateHubConfig,
	type HubFieldErrors,
} from "~/components/HubSettingsPanel";
import type { HubConfigSettings, SecuritySettings } from "~/types";
import { TEXT_MODELS } from "shared/mailbox-settings";

// Placeholder shown in the textarea when no custom prompt is set.
// The authoritative default prompt lives in workers/agent/index.ts (DEFAULT_SYSTEM_PROMPT).
const PROMPT_PLACEHOLDER = `You are an email assistant that helps manage this inbox. You read emails, draft replies, and help organize conversations.\n\nWrite like a real person. Short, direct, flowing prose. Plain text only.\n\n(Leave empty to use the full built-in default prompt)`;

interface OrgSettingsShape {
	agentSystemPrompt?: string;
	agentModel?: string;
	autoDraft?: { enabled?: boolean };
	security?: SecuritySettings;
	intel?: { hub?: HubConfigSettings };
}

/** Pill rendered next to a per-mailbox field. The "Inherited from org"
 *  variant doubles as a click target — the user has to type / toggle to
 *  promote the field to an override, which matches the resolver contract
 *  ("absent = inherit from one layer up"). */
function InheritanceBadge({ inherited }: { inherited: boolean }) {
	return inherited ? (
		<Badge variant="secondary" data-testid="inherited-badge">Inherited from org</Badge>
	) : (
		<Badge variant="primary" data-testid="override-badge">Override</Badge>
	);
}

export default function SettingsRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const feedback = useFeedback();
	const { data: mailbox } = useMailbox(mailboxId);
	const { data: orgData } = useOrgSettings();
	const updateMailboxMutation = useUpdateMailbox();
	const { models: availableModels } = useTextModels();

	const orgSettings = (orgData?.settings ?? {}) as OrgSettingsShape;

	const [displayName, setDisplayName] = useState("");

	// Per-field override flags + values. `override` is true when the
	// mailbox tier supplies its own value (and the save will write it);
	// false when the field inherits the org tier (save omits it so the
	// PUT-side stripDefaultEqual + the resolver's absent-key-inherits
	// semantics keep the inheritance chain alive).
	const [promptOverride, setPromptOverride] = useState(false);
	const [agentPrompt, setAgentPrompt] = useState("");

	const [autoDraftOverride, setAutoDraftOverride] = useState(false);
	const [autoDraftEnabled, setAutoDraftEnabled] = useState(true);

	const [modelOverride, setModelOverride] = useState(false);
	const [modelChoice, setModelChoice] = useState<string>(TEXT_MODELS[0]);
	const [customModel, setCustomModel] = useState("");

	const [securityOverride, setSecurityOverride] = useState(false);
	const [security, setSecurity] = useState<SecuritySettings | undefined>(undefined);

	const [hubOverride, setHubOverride] = useState(false);
	const [hub, setHub] = useState<HubConfigSettings | undefined>(undefined);
	const [hubErrors, setHubErrors] = useState<HubFieldErrors | undefined>(undefined);

	const [isSaving, setIsSaving] = useState(false);

	useEffect(() => {
		if (!mailbox) return;
		const s = mailbox.settings as
			| ({
					autoDraft?: { enabled?: boolean };
					agentModel?: string;
			  } & Record<string, unknown>)
			| undefined;

		setDisplayName(mailbox.settings?.fromName || mailbox.name || "");

		// Prompt: override when mailbox supplies a non-empty value.
		const mailboxPrompt = mailbox.settings?.agentSystemPrompt;
		if (mailboxPrompt && mailboxPrompt.trim()) {
			setPromptOverride(true);
			setAgentPrompt(mailboxPrompt);
		} else {
			setPromptOverride(false);
			setAgentPrompt(orgSettings.agentSystemPrompt ?? "");
		}

		// autoDraft: override when mailbox sets the block at all.
		if (s?.autoDraft) {
			setAutoDraftOverride(true);
			setAutoDraftEnabled(s.autoDraft.enabled ?? true);
		} else {
			setAutoDraftOverride(false);
			setAutoDraftEnabled(orgSettings.autoDraft?.enabled ?? true);
		}

		// agentModel
		const initialModel = s?.agentModel;
		if (initialModel) {
			setModelOverride(true);
			if (availableModels.includes(initialModel)) {
				setModelChoice(initialModel);
				setCustomModel("");
			} else {
				setModelChoice("__custom__");
				setCustomModel(initialModel);
			}
		} else {
			setModelOverride(false);
			const orgModel = orgSettings.agentModel ?? availableModels[0] ?? TEXT_MODELS[0];
			if (availableModels.includes(orgModel)) {
				setModelChoice(orgModel);
				setCustomModel("");
			} else {
				setModelChoice("__custom__");
				setCustomModel(orgModel);
			}
		}

		// security: override when the block is present at all.
		if (mailbox.settings?.security) {
			setSecurityOverride(true);
			setSecurity(mailbox.settings.security);
		} else {
			setSecurityOverride(false);
			setSecurity(orgSettings.security);
		}

		// intel.hub: override when the mailbox sets one.
		if (mailbox.settings?.intel?.hub) {
			setHubOverride(true);
			setHub(mailbox.settings.intel.hub);
		} else {
			setHubOverride(false);
			setHub(orgSettings.intel?.hub);
		}
		setHubErrors(undefined);

		// availableModels intentionally omitted from deps — see commit
		// message for the rationale (re-running this effect would clobber
		// edits when the dynamic models list resolves).
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [mailbox, orgData]);

	const handleSave = async () => {
		if (!mailbox || !mailboxId) return;

		const resolvedModel = modelChoice === "__custom__" ? customModel.trim() : modelChoice;
		if (modelOverride && modelChoice === "__custom__" && !resolvedModel) {
			feedback.error("Custom model cannot be empty");
			return;
		}
		if (modelOverride && resolvedModel && !resolvedModel.startsWith("@cf/")) {
			feedback.error("Model must start with @cf/");
			return;
		}

		// Hub validation runs only when override is on; if the mailbox
		// is inheriting, we don't write any intel.hub key and the worker
		// resolver picks up the org-level config instead.
		let nextIntel: { hub?: HubConfigSettings } | undefined;
		if (hubOverride) {
			const hubValidation = validateHubConfig(hub);
			setHubErrors(hubValidation ?? undefined);
			if (hubValidation) {
				feedback.error("Fix the threat-intel hub fields before saving.");
				return;
			}
			const normalizedHub = normalizeHubConfig(hub);
			if (normalizedHub) {
				const existingIntel = mailbox.settings?.intel ?? {};
				nextIntel = { ...existingIntel, hub: normalizedHub };
			}
		} else {
			// Preserve any other intel.* keys (#29 peer subscriptions, etc.)
			// while explicitly removing the hub override.
			const existingIntel = { ...(mailbox.settings?.intel ?? {}) };
			delete existingIntel.hub;
			nextIntel = Object.keys(existingIntel).length > 0 ? existingIntel : undefined;
		}

		setIsSaving(true);
		// Build the PUT payload. Per audit Q5/Q6/Q8: undefined fields get
		// stripped server-side via stripDefaultEqual (PR1) so the resolver
		// can fall through to the org tier on the next read.
		const settings = {
			...mailbox.settings,
			fromName: displayName,
			agentSystemPrompt: promptOverride ? agentPrompt.trim() || undefined : undefined,
			autoDraft: autoDraftOverride ? { enabled: autoDraftEnabled } : undefined,
			agentModel: modelOverride ? resolvedModel || undefined : undefined,
			security: securityOverride ? security : undefined,
			intel: nextIntel,
		};
		try {
			await updateMailboxMutation.mutateAsync({ mailboxId, settings });
			feedback.success("Settings saved!");
		} catch {
			feedback.error("Failed to save settings");
		} finally {
			setIsSaving(false);
		}
	};

	const resetPrompt = () => {
		setPromptOverride(false);
		setAgentPrompt(orgSettings.agentSystemPrompt ?? "");
	};
	const resetAutoDraft = () => {
		setAutoDraftOverride(false);
		setAutoDraftEnabled(orgSettings.autoDraft?.enabled ?? true);
	};
	const resetModel = () => {
		setModelOverride(false);
		const orgModel = orgSettings.agentModel ?? availableModels[0] ?? TEXT_MODELS[0];
		if (availableModels.includes(orgModel)) {
			setModelChoice(orgModel);
			setCustomModel("");
		} else {
			setModelChoice("__custom__");
			setCustomModel(orgModel);
		}
	};
	const resetSecurity = () => {
		setSecurityOverride(false);
		setSecurity(orgSettings.security);
	};
	const resetHub = () => {
		setHubOverride(false);
		setHub(orgSettings.intel?.hub);
		setHubErrors(undefined);
	};

	if (!mailbox) {
		return (
			<div className="flex justify-center py-20">
				<Loader size="lg" />
			</div>
		);
	}

	return (
		<div className="max-w-2xl px-4 py-4 md:px-8 md:py-6 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-2">Settings</h1>
			<p className="text-xs text-ink-3 mb-6">
				Per-mailbox overrides. Fields marked{" "}
				<Badge variant="secondary">Inherited from org</Badge> use the org-wide
				default — manage those at <Link to="/settings" className="underline">/settings</Link>.
				Editing a field here promotes it to an override that wins for this
				mailbox; security and intel.hub overrides replace the entire org
				block whole (no deep-merge across tiers).
			</p>

			<div className="space-y-6">
				{/* Account — strictly per-mailbox, no inheritance. */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-4">Account</div>
					<div className="space-y-3">
						<Input
							label="Display Name"
							value={displayName}
							onChange={(e) => setDisplayName(e.target.value)}
						/>
						<Input label="Email" type="email" value={mailbox.email} disabled />
					</div>
				</div>

				{/* Agent System Prompt */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-4">
						<div className="flex items-center gap-2">
							<RobotIcon size={16} weight="duotone" className="text-ink-3" />
							<span className="text-sm font-medium text-ink">AI Agent Prompt</span>
							<InheritanceBadge inherited={!promptOverride} />
						</div>
						{promptOverride && (
							<Button
								variant="ghost"
								size="xs"
								icon={<ArrowCounterClockwiseIcon size={14} />}
								onClick={resetPrompt}
								data-testid="reset-prompt"
							>
								Reset to inherited
							</Button>
						)}
					</div>
					<p className="text-xs text-ink-3 mb-3">
						{promptOverride
							? "This mailbox uses a custom prompt — overrides the org default."
							: "Inheriting the org-wide prompt. Type below to create an override."}
					</p>
					<textarea
						value={agentPrompt}
						onChange={(e) => {
							setAgentPrompt(e.target.value);
							setPromptOverride(true);
						}}
						placeholder={PROMPT_PLACEHOLDER}
						rows={12}
						className="w-full resize-y rounded-lg border border-line bg-paper-2 px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent font-mono leading-relaxed"
					/>
				</div>

				{/* Behavior */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-4">
						<div className="flex items-center gap-2">
							<span className="text-sm font-medium text-ink">Behavior</span>
						</div>
					</div>

					<label className="flex items-start justify-between gap-3 mb-5">
						<span className="flex flex-col">
							<span className="flex items-center gap-2 text-sm text-ink">
								Auto-draft replies
								<InheritanceBadge inherited={!autoDraftOverride} />
								{autoDraftOverride && (
									<button
										type="button"
										onClick={resetAutoDraft}
										className="text-xs text-ink-3 underline hover:text-ink"
										data-testid="reset-autodraft"
									>
										Reset
									</button>
								)}
							</span>
							<span className="text-xs text-ink-3 mt-1 max-w-md">
								Generate a draft reply automatically when new mail arrives.
								Drafts are never sent without explicit confirmation.
							</span>
						</span>
						<input
							type="checkbox"
							checked={autoDraftEnabled}
							onChange={(e) => {
								setAutoDraftEnabled(e.target.checked);
								setAutoDraftOverride(true);
							}}
							className="mt-1 h-4 w-4 accent-accent shrink-0"
							aria-label="Auto-draft replies"
						/>
					</label>

					<div>
						<div className="flex items-center justify-between mb-1.5">
							<label htmlFor="agent-model-select" className="block text-sm text-ink">
								<span className="inline-flex items-center gap-2">
									Agent model
									<InheritanceBadge inherited={!modelOverride} />
								</span>
							</label>
							{modelOverride && (
								<button
									type="button"
									onClick={resetModel}
									className="text-xs text-ink-3 underline hover:text-ink"
									data-testid="reset-model"
								>
									Reset to inherited
								</button>
							)}
						</div>
						<select
							id="agent-model-select"
							value={modelChoice}
							onChange={(e) => {
								setModelChoice(e.target.value);
								setModelOverride(true);
							}}
							className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink focus:outline-none focus:ring-1 focus:ring-accent"
						>
							{availableModels.map((m) => (
								<option key={m} value={m}>{m}</option>
							))}
							<option value="__custom__">Custom…</option>
						</select>
						{modelChoice === "__custom__" && (
							<input
								type="text"
								placeholder="@cf/your/model"
								value={customModel}
								onChange={(e) => {
									setCustomModel(e.target.value);
									setModelOverride(true);
								}}
								className="mt-2 w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent"
							/>
						)}
						<p className="text-xs text-ink-3 mt-2">
							Used for chat and auto-draft. Custom values must start with{" "}
							<code className="pp-mono">@cf/</code>.
						</p>
					</div>
				</div>

				{/* Security — block-level inheritance. Override carries the WHOLE
				    security object (incl. allowlists). v1 has no extend-merge for
				    arrays; tracked as #149. */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-3">
						<span className="text-sm font-medium text-ink inline-flex items-center gap-2">
							Security
							<InheritanceBadge inherited={!securityOverride} />
						</span>
						{securityOverride && (
							<button
								type="button"
								onClick={resetSecurity}
								className="text-xs text-ink-3 underline hover:text-ink"
								data-testid="reset-security"
							>
								Reset to inherited
							</button>
						)}
					</div>
					{!securityOverride && (
						<div className="rounded-md border border-line bg-paper-2 px-3 py-2 mb-3 text-xs text-ink-3">
							Inheriting the org-wide security block. Editing below promotes
							this mailbox to an override that <strong>replaces the entire
							org security block</strong> — including allowlists, thresholds,
							and trusted authserv-ids. Cross-tier extend-merge for allowlist
							arrays is tracked as a follow-up.
						</div>
					)}
					<SecuritySettingsPanel
						value={security}
						onChange={(next) => {
							setSecurity(next);
							setSecurityOverride(true);
						}}
					/>
				</div>

				{/* Threat-intel hub (#97) — block-level inheritance. */}
				<div className="pp-card p-5">
					<div className="flex items-center justify-between mb-3">
						<span className="text-sm font-medium text-ink inline-flex items-center gap-2">
							Threat-intel hub
							<InheritanceBadge inherited={!hubOverride} />
						</span>
						{hubOverride && (
							<button
								type="button"
								onClick={resetHub}
								className="text-xs text-ink-3 underline hover:text-ink"
								data-testid="reset-hub"
							>
								Reset to inherited
							</button>
						)}
					</div>
					{!hubOverride && (
						<div className="rounded-md border border-line bg-paper-2 px-3 py-2 mb-3 text-xs text-ink-3">
							Inheriting the org-wide hub config. Editing below creates a
							per-mailbox hub that replaces the org config whole.
						</div>
					)}
					<HubSettingsPanel
						value={hub}
						onChange={(next) => {
							setHub(next);
							setHubOverride(true);
							if (hubErrors) setHubErrors(validateHubConfig(next) ?? undefined);
						}}
						errors={hubErrors}
					/>
				</div>

				{/* Save */}
				<div className="flex justify-end">
					<Button variant="primary" onClick={handleSave} loading={isSaving}>
						Save Changes
					</Button>
				</div>
			</div>
		</div>
	);
}
