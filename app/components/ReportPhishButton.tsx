// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

import { Button, Tooltip, useKumoToastManager } from "@cloudflare/kumo";
import { ShieldWarningIcon } from "@phosphor-icons/react";
import { useNavigate } from "react-router";
import { useState } from "react";

/**
 * Convert an email into a local case and (future milestones) push anonymized
 * observables to the configured community hub. Safe to click multiple times —
 * the server creates one case per click, so the user can manage duplicates.
 */
export default function ReportPhishButton({
	mailboxId,
	emailId,
}: {
	mailboxId?: string;
	emailId: string;
}) {
	const navigate = useNavigate();
	const toast = useKumoToastManager();
	const [pending, setPending] = useState(false);

	const handle = async () => {
		if (!mailboxId) return;
		setPending(true);
		try {
			const res = await fetch(
				`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/cases/report-phish`,
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify({ emailId }),
				},
			);
			if (!res.ok) throw new Error(await res.text());
			const data = (await res.json()) as { caseId?: string };
			toast.add({ title: "Phish reported", description: "A case was opened." });
			if (data.caseId) navigate(`/mailbox/${encodeURIComponent(mailboxId)}/cases/${data.caseId}`);
		} catch (e) {
			toast.add({ title: "Report failed", description: (e as Error).message, variant: "error" });
		} finally {
			setPending(false);
		}
	};

	return (
		<Tooltip content="Report as phish" side="bottom" asChild>
			<Button
				variant="ghost"
				shape="square"
				size="sm"
				icon={<ShieldWarningIcon size={18} />}
				onClick={handle}
				loading={pending}
				aria-label="Report as phish"
			/>
		</Tooltip>
	);
}
