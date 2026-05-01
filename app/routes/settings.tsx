// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Badge, Button, Input, Loader } from "@cloudflare/kumo";
import { RobotIcon, ArrowCounterClockwiseIcon } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { useParams } from "react-router";
import { useFeedback } from "~/lib/feedback";
import { useMailbox, useUpdateMailbox } from "~/queries/mailboxes";
import { useTextModels } from "~/queries/text-models";
import { SecuritySettingsPanel } from "~/components/SecuritySettingsPanel";
import type { SecuritySettings } from "~/types";
import {
	DEFAULT_CLASSIFIER_MODEL,
	DEFAULT_DRAFT_VERIFIER_MODEL,
	DEFAULT_INJECTION_SCANNER_MODEL,
	TEXT_MODELS,
} from "shared/mailbox-settings";

// Placeholder shown in the textarea when no custom prompt is set.
// The authoritative default prompt lives in workers/agent/index.ts (DEFAULT_SYSTEM_PROMPT).
const PROMPT_PLACEHOLDER = `You are an email assistant that helps manage this inbox. You read emails, draft replies, and help organize conversations.\n\nWrite like a real person. Short, direct, flowing prose. Plain text only.\n\n(Leave empty to use the full built-in default prompt)`;

export default function SettingsRoute() {
	const { mailboxId } = useParams<{ mailboxId: string }>();
	const feedback = useFeedback();
	const { data: mailbox } = useMailbox(mailboxId);
	const updateMailboxMutation = useUpdateMailbox();
	const { models: availableModels } = useTextModels();

	const [displayName, setDisplayName] = useState("");
	const [agentPrompt, setAgentPrompt] = useState("");
	const [security, setSecurity] = useState<SecuritySettings | undefined>(undefined);
	const [autoDraftEnabled, setAutoDraftEnabled] = useState(true);
	const [modelChoice, setModelChoice] = useState<string>(TEXT_MODELS[0]);
	const [customModel, setCustomModel] = useState("");
	const [injectionScannerModel, setInjectionScannerModel] = useState("");
	const [draftVerifierModel, setDraftVerifierModel] = useState("");
	const [classifierModel, setClassifierModel] = useState("");
	const [isSaving, setIsSaving] = useState(false);

	useEffect(() => {
		if (mailbox) {
			setDisplayName(mailbox.settings?.fromName || mailbox.name || "");
			setAgentPrompt(mailbox.settings?.agentSystemPrompt || "");
			setSecurity(mailbox.settings?.security);

			const behavior = mailbox.settings as
				| {
						autoDraft?: { enabled?: boolean };
						agentModel?: string;
						injectionScannerModel?: string;
						draftVerifierModel?: string;
						classifierModel?: string;
				  }
				| undefined;
			const enabled = behavior?.autoDraft?.enabled;
			setAutoDraftEnabled(enabled === undefined ? true : enabled);

			const m = behavior?.agentModel ?? availableModels[0] ?? TEXT_MODELS[0];
			if (availableModels.includes(m)) {
				setModelChoice(m);
				setCustomModel("");
			} else {
				setModelChoice("__custom__");
				setCustomModel(m);
			}

			setInjectionScannerModel(behavior?.injectionScannerModel ?? "");
			setDraftVerifierModel(behavior?.draftVerifierModel ?? "");
			setClassifierModel(behavior?.classifierModel ?? "");
		}
		// `availableModels` is intentionally not in the dep list — re-running
		// this effect when the dynamic list resolves would reset every other
		// piece of edited state (auto-draft toggle, custom prompt, …) back to
		// the saved values, silently undoing the user's edits. The initial
		// fallback list (`[...TEXT_MODELS]`) is stable enough to map saved
		// models on first render.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [mailbox]);

	const handleSave = async () => {
		if (!mailbox || !mailboxId) return;

		const resolvedModel =
			modelChoice === "__custom__" ? customModel.trim() : modelChoice;
		if (modelChoice === "__custom__" && !resolvedModel) {
			feedback.error("Custom model cannot be empty");
			return;
		}
		if (resolvedModel && !resolvedModel.startsWith("@cf/")) {
			feedback.error("Model must start with @cf/");
			return;
		}

		// Validate optional security-model overrides — same `@cf/` rule as
		// the agent model. Empty value means "use default" (#67).
		const advancedModelInputs: Array<{ label: string; value: string }> = [
			{ label: "Injection scanner", value: injectionScannerModel.trim() },
			{ label: "Draft verifier", value: draftVerifierModel.trim() },
			{ label: "Classifier", value: classifierModel.trim() },
		];
		for (const m of advancedModelInputs) {
			if (m.value && !m.value.startsWith("@cf/")) {
				feedback.error(`${m.label} model must start with @cf/`);
				return;
			}
		}

		setIsSaving(true);
		const settings = {
			...mailbox.settings,
			fromName: displayName,
			agentSystemPrompt: agentPrompt.trim() || undefined,
			security,
			autoDraft: { enabled: autoDraftEnabled },
			agentModel: resolvedModel || availableModels[0] || TEXT_MODELS[0],
			injectionScannerModel: injectionScannerModel.trim() || undefined,
			draftVerifierModel: draftVerifierModel.trim() || undefined,
			classifierModel: classifierModel.trim() || undefined,
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

	const handleResetPrompt = () => {
		setAgentPrompt("");
	};

	if (!mailbox) {
		return (
			<div className="flex justify-center py-20">
				<Loader size="lg" />
			</div>
		);
	}

	const isCustomPrompt = agentPrompt.trim().length > 0;

	return (
		<div className="max-w-2xl px-4 py-4 md:px-8 md:py-6 h-full overflow-y-auto">
			<h1 className="pp-serif text-ink mb-6">Settings</h1>

			<div className="space-y-6">
				{/* Account */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-4">
						Account
					</div>
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
							<span className="text-sm font-medium text-ink">
								AI Agent Prompt
							</span>
							{isCustomPrompt ? (
								<Badge variant="primary">Custom</Badge>
							) : (
								<Badge variant="secondary">Default</Badge>
							)}
						</div>
						{isCustomPrompt && (
							<Button
								variant="ghost"
								size="xs"
								icon={<ArrowCounterClockwiseIcon size={14} />}
								onClick={handleResetPrompt}
							>
								Reset to default
							</Button>
						)}
					</div>
					<p className="text-xs text-ink-3 mb-3">
						Customize how the AI agent behaves for this mailbox.
						Leave empty to use the built-in default prompt.
					</p>
					<textarea
						value={agentPrompt}
						onChange={(e) => setAgentPrompt(e.target.value)}
						placeholder={PROMPT_PLACEHOLDER}
						rows={12}
						className="w-full resize-y rounded-lg border border-line bg-paper-2 px-3 py-2 text-xs text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent font-mono leading-relaxed"
					/>
					<p className="text-xs text-ink-3 mt-2">
						The prompt is sent as the system message to the AI model.
						It controls the agent's personality, writing style, and behavior rules.
					</p>
				</div>

				{/* Behavior — auto-draft toggle + agent model picker */}
				<div className="pp-card p-5">
					<div className="text-sm font-medium text-ink mb-4">Behavior</div>

					<label className="flex items-start justify-between gap-3 mb-5">
						<span className="flex flex-col">
							<span className="text-sm text-ink">Auto-draft replies</span>
							<span className="text-xs text-ink-3 mt-1 max-w-md">
								Generate a draft reply automatically when new mail arrives.
								Drafts are never sent without explicit confirmation.
							</span>
						</span>
						<input
							type="checkbox"
							checked={autoDraftEnabled}
							onChange={(e) => setAutoDraftEnabled(e.target.checked)}
							className="mt-1 h-4 w-4 accent-accent shrink-0"
							aria-label="Auto-draft replies"
						/>
					</label>

					<div>
						<label htmlFor="agent-model-select" className="block text-sm text-ink mb-1.5">
							Agent model
						</label>
						<select
							id="agent-model-select"
							value={modelChoice}
							onChange={(e) => setModelChoice(e.target.value)}
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
								onChange={(e) => setCustomModel(e.target.value)}
								className="mt-2 w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent"
							/>
						)}
						<p className="text-xs text-ink-3 mt-2">
							Used for chat and auto-draft. Custom values must start with{" "}
							<code className="pp-mono">@cf/</code>.
						</p>
					</div>

					{/* Advanced — security-critical model overrides (#67). Hidden
					    behind a disclosure so the regular Settings page stays
					    minimal. Wrong value can let real prompt injection
					    through, so leave empty to keep the tested defaults. */}
					<details className="mt-5 group">
						<summary className="cursor-pointer text-xs font-medium text-ink-2 hover:text-ink select-none">
							Advanced — security model overrides
						</summary>
						<div className="mt-3 space-y-4 border-l-2 border-line pl-4">
							<p className="text-xs text-ink-3">
								These models drive security-critical paths. Leave empty to
								use the tested defaults shown as placeholders. Wrong choices
								can degrade detection — only override if you know what you
								are doing.
							</p>
							<div>
								<label
									htmlFor="advanced-injection-model"
									className="block text-xs text-ink mb-1"
								>
									Prompt-injection scanner
								</label>
								<input
									id="advanced-injection-model"
									type="text"
									placeholder={DEFAULT_INJECTION_SCANNER_MODEL}
									value={injectionScannerModel}
									onChange={(e) => setInjectionScannerModel(e.target.value)}
									className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
								/>
							</div>
							<div>
								<label
									htmlFor="advanced-verifier-model"
									className="block text-xs text-ink mb-1"
								>
									Draft verifier
								</label>
								<input
									id="advanced-verifier-model"
									type="text"
									placeholder={DEFAULT_DRAFT_VERIFIER_MODEL}
									value={draftVerifierModel}
									onChange={(e) => setDraftVerifierModel(e.target.value)}
									className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
								/>
							</div>
							<div>
								<label
									htmlFor="advanced-classifier-model"
									className="block text-xs text-ink mb-1"
								>
									LLM classifier
								</label>
								<input
									id="advanced-classifier-model"
									type="text"
									placeholder={DEFAULT_CLASSIFIER_MODEL}
									value={classifierModel}
									onChange={(e) => setClassifierModel(e.target.value)}
									className="w-full rounded-md border border-line bg-paper-2 px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:outline-none focus:ring-1 focus:ring-accent pp-mono"
								/>
							</div>
						</div>
					</details>
				</div>

				{/* Security */}
				<SecuritySettingsPanel value={security} onChange={setSecurity} />

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
