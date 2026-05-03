// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Manual case creation dialog (issue #190, extended in #194).
 *
 * The "+ Manual case" button on `/mailbox/:mailboxId/cases` opens this
 * dialog. Submitting POSTs to the existing endpoint
 *   `POST /api/v1/mailboxes/:mailboxId/cases`
 * which validates against `CreateCaseBody` (workers/routes/cases.ts:29):
 *
 *   { title (req), notes?, emailId?, observables?, score? }
 *
 * Surfaces:
 *   - title (required), notes, emailId — the v1 surface (#190).
 *   - observables — repeating editor: `kind` dropdown +
 *     `value` input. Add/remove rows. Empty rows are silently
 *     dropped before POST. When the array would be empty post-drop,
 *     we omit `observables` from the body entirely (the schema
 *     marks it `.optional()`).
 *   - score — optional integer 0-100. Empty by default. When empty
 *     on submit, we OMIT `score` from the body (do NOT send `null`).
 *     `report-phish` is the path that derives a verdict score
 *     automatically; manual creates leave it null on purpose, and
 *     omitting lets the worker default it. Invalid input
 *     (non-integer / out-of-range) shows an inline message and
 *     blocks submit.
 *
 * Status is hardcoded to `"open"` by the DO's `createCase` impl —
 * not exposed on the schema, so we don't render a status `<select>`.
 *
 * Validation errors are surfaced field-by-field from the worker's
 * `parsed.error.flatten().fieldErrors` shape. Network / 500-class
 * failures fall back to a generic toast via `useFeedback`.
 *
 * Per-row observable errors: zod's `flatten()` collapses nested
 * issues into `formErrors`, so the worker's current response can
 * only carry an `observables` top-level error (e.g. "Required").
 * We surface that above the editor. If the response ever grows
 * `observables.<i>.<field>` keys (e.g. via a richer error
 * serializer), `observableRowErrors` below maps them to the
 * matching row inline.
 */

import { Button, Dialog, Input, Text } from "@cloudflare/kumo";
import {
	type FormEvent,
	useCallback,
	useEffect,
	useMemo,
	useState,
} from "react";
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

/**
 * Set of `kind` values rendered by the case-detail observable list
 * (`OBSERVABLE_TONE` at app/routes/case-detail.tsx:37). Keep these in
 * sync — a `kind` not in that map renders muted on case-detail.
 */
const OBSERVABLE_KINDS = ["email", "url", "domain", "ipv4", "ipv6"] as const;
type ObservableKind = (typeof OBSERVABLE_KINDS)[number];

interface ObservableRow {
	/** Stable key for React. Not sent to the worker. */
	key: string;
	kind: ObservableKind;
	value: string;
}

type FieldErrors = Partial<
	Record<"title" | "notes" | "emailId" | "observables" | "score", string>
>;

/**
 * Per-row error map keyed by observable row index. Only populated when
 * the worker's 400 response includes nested keys like
 * `observables.0.value` — current `flatten()` output won't carry these,
 * but the surface is wired so a future richer error response renders
 * inline next to the offending row.
 */
type ObservableRowErrors = Record<number, { kind?: string; value?: string }>;

let _rowKeySeq = 0;
function nextRowKey(): string {
	_rowKeySeq += 1;
	return `obs-${_rowKeySeq}`;
}

function emptyRow(): ObservableRow {
	return { key: nextRowKey(), kind: "email", value: "" };
}

/**
 * Validate score input. Returns `{ value: number }` for a parseable
 * integer in [0, 100], `{ value: null }` for empty/whitespace (omit
 * from body), or `{ error }` for invalid input (block submit).
 */
function parseScore(raw: string): { value: number | null } | { error: string } {
	const trimmed = raw.trim();
	if (trimmed === "") return { value: null };
	if (!/^-?\d+$/.test(trimmed)) {
		return { error: "Score must be a whole number between 0 and 100." };
	}
	const n = Number(trimmed);
	if (!Number.isInteger(n) || n < 0 || n > 100) {
		return { error: "Score must be a whole number between 0 and 100." };
	}
	return { value: n };
}

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
	const [observables, setObservables] = useState<ObservableRow[]>(() => [
		emptyRow(),
	]);
	const [score, setScore] = useState("");
	const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
	const [observableRowErrors, setObservableRowErrors] =
		useState<ObservableRowErrors>({});
	const [submitting, setSubmitting] = useState(false);

	const reset = useCallback(() => {
		setTitle("");
		setNotes("");
		setEmailId("");
		setObservables([emptyRow()]);
		setScore("");
		setFieldErrors({});
		setObservableRowErrors({});
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

	// Live-validate score as the user types so the inline error is in
	// sync with the disabled-submit state. Empty string is valid (=> omit).
	const scoreValidation = useMemo(() => parseScore(score), [score]);
	const scoreError =
		"error" in scoreValidation ? scoreValidation.error : undefined;

	const addObservableRow = () => {
		setObservables((rows) => [...rows, emptyRow()]);
	};

	const removeObservableRow = (key: string) => {
		setObservables((rows) => {
			const next = rows.filter((r) => r.key !== key);
			// Always keep at least one row in the editor — adds back an
			// empty row if the user removes the last populated one. The
			// row is dropped at submit time if still empty.
			return next.length > 0 ? next : [emptyRow()];
		});
		// Drop any stale row error for the removed row's index. The
		// reindex isn't perfect (errors stick to the old indices), but
		// any new submit clears them anyway.
		setObservableRowErrors({});
	};

	const updateObservableRow = (
		key: string,
		patch: Partial<Pick<ObservableRow, "kind" | "value">>,
	) => {
		setObservables((rows) =>
			rows.map((r) => (r.key === key ? { ...r, ...patch } : r)),
		);
	};

	const handleSubmit = async (e: FormEvent) => {
		e.preventDefault();
		if (!mailboxId || submitting) return;
		// Block submit on a client-side score error.
		if (scoreError) return;
		setFieldErrors({});
		setObservableRowErrors({});

		const body: Record<string, unknown> = { title: title.trim() };
		const trimmedNotes = notes.trim();
		if (trimmedNotes) body.notes = trimmedNotes;
		const trimmedEmailId = emailId.trim();
		if (trimmedEmailId) body.emailId = trimmedEmailId;

		// Drop empty rows. A row is "empty" when its value is blank
		// after trim — kind always has a default, so an unset kind
		// isn't possible here.
		const populatedObservables = observables
			.map((r) => ({ kind: r.kind, value: r.value.trim() }))
			.filter((r) => r.value.length > 0);
		if (populatedObservables.length > 0) {
			body.observables = populatedObservables;
		}

		// Score: only attach when set (validated above). When empty,
		// omit entirely — the worker defaults it. Per #194 acceptance:
		// do NOT send `null`.
		if ("value" in scoreValidation && scoreValidation.value !== null) {
			body.score = scoreValidation.value;
		}

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
				const errBody = (await res.json().catch(() => null)) as
					| { error?: { fieldErrors?: Record<string, string[]> } }
					| null;
				const fe = errBody?.error?.fieldErrors ?? {};
				setFieldErrors({
					title: fe.title?.[0],
					notes: fe.notes?.[0],
					emailId: fe.emailId?.[0],
					observables: fe.observables?.[0],
					score: fe.score?.[0],
				});
				// Map any nested-key errors to the matching row index.
				// Pattern: `observables.<i>.<field>`. Stock zod
				// `flatten()` won't emit these, but the surface is
				// wired so a richer serializer renders inline.
				const rowErrors: ObservableRowErrors = {};
				for (const [k, msgs] of Object.entries(fe)) {
					const m = /^observables\.(\d+)\.(kind|value)$/.exec(k);
					if (m && msgs && msgs.length > 0) {
						const idx = Number(m[1]);
						const field = m[2] as "kind" | "value";
						rowErrors[idx] = { ...rowErrors[idx], [field]: msgs[0] };
					}
				}
				setObservableRowErrors(rowErrors);
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

	const submitDisabled =
		!title.trim() || !mailboxId || Boolean(scoreError);

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

					{/* Observables editor (#194). */}
					<div>
						<span className="text-sm font-medium text-ink mb-1.5 block">
							Observables (optional)
						</span>
						<div className="space-y-2">
							{observables.map((row, idx) => {
								const rowErr = observableRowErrors[idx];
								return (
									<div key={row.key}>
										<div className="flex gap-2 items-start">
											<select
												aria-label={`Observable kind ${idx + 1}`}
												value={row.kind}
												onChange={(e) =>
													updateObservableRow(row.key, {
														kind: e.target.value as ObservableKind,
													})
												}
												className="rounded-md border border-line bg-paper px-2 py-1.5 text-[13px] text-ink focus:outline-none focus:border-line-strong"
											>
												{OBSERVABLE_KINDS.map((k) => (
													<option key={k} value={k}>
														{k}
													</option>
												))}
											</select>
											<input
												type="text"
												aria-label={`Observable value ${idx + 1}`}
												placeholder="value"
												value={row.value}
												onChange={(e) =>
													updateObservableRow(row.key, {
														value: e.target.value,
													})
												}
												maxLength={500}
												className="flex-1 rounded-md border border-line bg-paper px-3 py-1.5 text-[13px] text-ink placeholder:text-ink-3 focus:outline-none focus:border-line-strong"
												aria-invalid={rowErr?.value ? true : undefined}
											/>
											<Button
												type="button"
												variant="secondary"
												size="sm"
												onClick={() => removeObservableRow(row.key)}
												aria-label={`Remove observable ${idx + 1}`}
											>
												Remove
											</Button>
										</div>
										{rowErr?.kind ? (
											<Text variant="error" size="sm">
												{rowErr.kind}
											</Text>
										) : null}
										{rowErr?.value ? (
											<Text variant="error" size="sm">
												{rowErr.value}
											</Text>
										) : null}
									</div>
								);
							})}
						</div>
						<div className="mt-2">
							<Button
								type="button"
								variant="secondary"
								size="sm"
								onClick={addObservableRow}
							>
								Add observable
							</Button>
						</div>
						{fieldErrors.observables ? (
							<Text variant="error" size="sm">
								{fieldErrors.observables}
							</Text>
						) : null}
					</div>

					{/* Score override (#194). */}
					<div>
						<Input
							label="Score override (optional, 0-100)"
							placeholder="leave blank for none"
							size="sm"
							inputMode="numeric"
							value={score}
							onChange={(e) => setScore(e.target.value)}
							aria-invalid={
								scoreError || fieldErrors.score ? true : undefined
							}
						/>
						{scoreError ? (
							<Text variant="error" size="sm">
								{scoreError}
							</Text>
						) : fieldErrors.score ? (
							<Text variant="error" size="sm">
								{fieldErrors.score}
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
							disabled={submitDisabled}
						>
							Create case
						</Button>
					</div>
				</form>
			</Dialog>
		</Dialog.Root>
	);
}
