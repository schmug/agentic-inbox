// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Manual case creation dialog (issue #190).
 *
 * The "+ Manual case" button on `/mailbox/:mailboxId/cases` opens this
 * dialog. Submitting POSTs to the existing endpoint
 *   `POST /api/v1/mailboxes/:mailboxId/cases`
 * which validates against `CreateCaseBody` (workers/routes/cases.ts:29):
 *
 *   { title (req), notes?, emailId?, observables?, score? }
 *
 * v1 surfaces only `title`, `notes`, and `emailId`. `observables` and
 * `score` are intentionally deferred — the worker accepts them, but the
 * UI for repeating observable kind/value pairs is its own design problem
 * and `score` is auto-derived from the originating email's verdict on
 * the report-phish path. New manual cases land at status `"open"` —
 * that's hardcoded in the DO's `createCase` impl, not exposed on the
 * schema, so we don't render a status `<select>`.
 *
 * Validation errors are surfaced field-by-field from the worker's
 * `parsed.error.flatten().fieldErrors` shape. Network / 500-class
 * failures fall back to a generic toast via `useFeedback`.
 */

import { Button, Dialog, Input, Text } from "@cloudflare/kumo";
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { useFeedback } from "~/lib/feedback";

export interface CreateCaseModalProps {
	open: boolean;
	mailboxId: string | undefined;
	onOpenChange: (open: boolean) => void;
	/**
	 * Called after a successful POST. The cases list page uses this to
	 * bump a `refreshKey` so its `useEffect` re-fetches, and to flip the
	 * visible tab to "open" so the new case is visible (it's hardcoded
	 * to "open" by the worker). No id is passed: the list refetch is the
	 * source of truth for what showed up.
	 */
	onCreated: () => void;
}

type FieldErrors = Partial<Record<"title" | "notes" | "emailId", string>>;

export default function CreateCaseModal({
	open,
	mailboxId,
	onOpenChange,
	onCreated,
}: CreateCaseModalProps) {
	const feedback = useFeedback();
	const [title, setTitle] = useState("");
	const [notes, setNotes] = useState("");
	const [emailId, setEmailId] = useState("");
	const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
	const [submitting, setSubmitting] = useState(false);

	const reset = useCallback(() => {
		setTitle("");
		setNotes("");
		setEmailId("");
		setFieldErrors({});
		setSubmitting(false);
	}, []);

	const handleOpenChange = useCallback(
		(next: boolean) => {
			if (!next) reset();
			onOpenChange(next);
		},
		[onOpenChange, reset],
	);

	// External `open=false` (e.g. parent closed it) should also reset.
	useEffect(() => {
		if (!open) reset();
		// `reset` is stable; dep on `open` only.
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [open]);

	const handleSubmit = async (e: FormEvent) => {
		e.preventDefault();
		if (!mailboxId || submitting) return;
		setFieldErrors({});

		const body: Record<string, unknown> = { title: title.trim() };
		const trimmedNotes = notes.trim();
		if (trimmedNotes) body.notes = trimmedNotes;
		const trimmedEmailId = emailId.trim();
		if (trimmedEmailId) body.emailId = trimmedEmailId;

		setSubmitting(true);
		try {
			const res = await fetch(
				`/api/v1/mailboxes/${encodeURIComponent(mailboxId)}/cases`,
				{
					method: "POST",
					headers: { "Content-Type": "application/json" },
					body: JSON.stringify(body),
				},
			);
			if (res.status === 400) {
				// Zod safeParse failure → render field-by-field, NOT a
				// generic toast (acceptance criterion).
				const errBody = (await res
					.json()
					.catch(() => null)) as
					| { error?: { fieldErrors?: Record<string, string[]> } }
					| null;
				const fe = errBody?.error?.fieldErrors ?? {};
				setFieldErrors({
					title: fe.title?.[0],
					notes: fe.notes?.[0],
					emailId: fe.emailId?.[0],
				});
				setSubmitting(false);
				return;
			}
			if (!res.ok) {
				feedback.error("Failed to create case");
				setSubmitting(false);
				return;
			}
			// Drain the body so the response is consumed cleanly.
			await res.json().catch(() => null);
			feedback.success("Case created");
			reset();
			onOpenChange(false);
			onCreated();
		} catch {
			feedback.error("Failed to create case");
			setSubmitting(false);
		}
	};

	return (
		<Dialog.Root open={open} onOpenChange={handleOpenChange}>
			<Dialog size="sm" className="p-6">
				<Dialog.Title className="text-base font-semibold mb-1">
					Create manual case
				</Dialog.Title>
				<Dialog.Description className="text-ink-3 text-sm mb-5">
					Open a case unattached to a specific email. New cases start
					with status <strong className="text-ink">open</strong>.
				</Dialog.Description>
				<form onSubmit={handleSubmit} className="space-y-4">
					<div>
						<Input
							label="Title"
							placeholder="e.g. Reported wire-transfer phish from finance@..."
							size="sm"
							value={title}
							onChange={(e) => setTitle(e.target.value)}
							required
							maxLength={500}
							aria-invalid={fieldErrors.title ? true : undefined}
						/>
						{fieldErrors.title ? (
							<Text variant="error" size="sm">
								{fieldErrors.title}
							</Text>
						) : null}
					</div>
					<div>
						<span className="text-sm font-medium text-ink mb-1.5 block">
							Notes (optional)
						</span>
						<textarea
							aria-label="Notes"
							placeholder="Context, links, what you've already done…"
							rows={4}
							className="w-full rounded-md border border-line bg-paper px-3 py-2 text-[13px] text-ink placeholder:text-ink-3 focus:outline-none focus:border-line-strong"
							value={notes}
							onChange={(e) => setNotes(e.target.value)}
						/>
						{fieldErrors.notes ? (
							<Text variant="error" size="sm">
								{fieldErrors.notes}
							</Text>
						) : null}
					</div>
					<div>
						<Input
							label="Linked email ID (optional)"
							placeholder="email_…"
							size="sm"
							value={emailId}
							onChange={(e) => setEmailId(e.target.value)}
							aria-invalid={fieldErrors.emailId ? true : undefined}
						/>
						{fieldErrors.emailId ? (
							<Text variant="error" size="sm">
								{fieldErrors.emailId}
							</Text>
						) : null}
					</div>
					<div className="flex justify-end gap-2 pt-2">
						<Dialog.Close
							render={(props) => (
								<Button
									{...props}
									variant="secondary"
									size="sm"
									type="button"
								>
									Cancel
								</Button>
							)}
						/>
						<Button
							type="submit"
							variant="primary"
							size="sm"
							loading={submitting}
							disabled={!title.trim() || !mailboxId}
						>
							Create case
						</Button>
					</div>
				</form>
			</Dialog>
		</Dialog.Root>
	);
}
