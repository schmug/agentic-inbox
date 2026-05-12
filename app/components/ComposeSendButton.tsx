// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * ComposeSendButton — renders the Send button in the composer UI.
 *
 * The button label and click behaviour change based on the preflight risk tier:
 *   Tier 0: "Send"         — normal submit, no extra step.
 *   Tier 1: "Send (re-auth)"  — step-up auth popup required before send.
 *   Tier 2: "Send (verify)"   — typed recipient confirmation + step-up auth.
 *
 * The confirm popup depends on the POST /api/v1/confirm endpoint (slice 2).
 * Until that ships, clicking Tier 1/2 shows a placeholder alert.
 */

import { Button } from "@cloudflare/kumo";
import { PaperPlaneTiltIcon } from "@phosphor-icons/react";
import { useState } from "react";
import type { PreflightTier } from "~/hooks/usePreflightTier";

interface ComposeSendButtonProps {
	tier: PreflightTier;
	isSending: boolean;
	isSavingDraft: boolean;
	/** Primary recipient address (the first "To" address). Used for Tier-2 typed confirmation. */
	primaryRecipient: string;
}

const TIER_LABEL: Record<PreflightTier, string> = {
	0: "Send",
	1: "Send (re-auth)",
	2: "Send (verify)",
};

const TIER_TEST_ID: Record<PreflightTier, string> = {
	0: "send-button-tier-0",
	1: "send-button-tier-1",
	2: "send-button-tier-2",
};

/**
 * Opens the /api/v1/confirm popup and waits for a postMessage token.
 * Resolves with the token string or null if the popup was closed without one.
 *
 * NOTE: slice 2 (the confirm endpoint + CF Access step-up app) is not yet
 * implemented. This function is wired up but will short-circuit to null until
 * the endpoint is live.
 */
async function openConfirmPopup(): Promise<string | null> {
	// Slice 2 placeholder — confirm endpoint not yet implemented.
	return null;
}

export default function ComposeSendButton({
	tier,
	isSending,
	isSavingDraft,
	primaryRecipient,
}: ComposeSendButtonProps) {
	const [tierConfirmPhrase, setTierConfirmPhrase] = useState("");

	// Tier-2 requires the user to type the primary recipient address before
	// proceeding. This state tracks whether the typed phrase matches.
	const phraseMatches =
		tier !== 2 || tierConfirmPhrase.trim().toLowerCase() === primaryRecipient.trim().toLowerCase();

	if (tier === 0) {
		return (
			<Button
				type="submit"
				variant="primary"
				size="sm"
				loading={isSending}
				disabled={isSavingDraft || isSending}
				icon={<PaperPlaneTiltIcon size={14} />}
				data-testid={TIER_TEST_ID[0]}
			>
				{isSending ? "Sending..." : TIER_LABEL[0]}
			</Button>
		);
	}

	// Tier 1 / Tier 2: clicking opens the confirm popup (placeholder until slice 2).
	async function handleTierSend(e: React.MouseEvent) {
		e.preventDefault();

		if (tier === 2 && !phraseMatches) {
			// User hasn't typed the correct recipient — do nothing; the input
			// below gives them the visual affordance.
			return;
		}

		// Placeholder for slice 2 — popup flow not yet configured.
		const token = await openConfirmPopup();
		if (token === null) {
			// Slice 2 not yet live — show user-visible notice and bail out.
			alert("Step-up auth not yet configured");
			return;
		}

		// token is available — the form submit handler on the parent will use it.
		// (postMessage relay wiring deferred to slice 2)
	}

	return (
		<div className="flex flex-col items-end gap-1">
			{tier === 2 && (
				<div className="flex items-center gap-2">
					<label className="text-xs text-ink-3">
						Type recipient address to confirm:
					</label>
					<input
						type="text"
						value={tierConfirmPhrase}
						onChange={(e) => setTierConfirmPhrase(e.target.value)}
						placeholder={primaryRecipient || "recipient@example.com"}
						className="border border-line rounded px-2 py-0.5 text-xs w-48"
						data-testid="tier-2-confirm-input"
					/>
				</div>
			)}
			<Button
				type="button"
				variant="primary"
				size="sm"
				loading={isSending}
				disabled={isSavingDraft || isSending || (tier === 2 && !phraseMatches)}
				icon={<PaperPlaneTiltIcon size={14} />}
				onClick={handleTierSend}
				data-testid={TIER_TEST_ID[tier]}
			>
				{isSending ? "Sending..." : TIER_LABEL[tier]}
			</Button>
		</div>
	);
}
