// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

import CaseDetailRoute from "~/routes/case-detail";
import { renderWithProviders } from "./test-utils";

// Per-case score is now persisted on the `cases` table at case-creation
// time (issue #126). The API returns it as `score: number | null`. The
// title bar renders <ScoreRing> when score is present and a muted "—"
// when null/undefined.
const baseCase = {
	id: "case_abc123",
	created_at: "2026-04-29T11:00:00Z",
	updated_at: "2026-04-29T11:30:00Z",
	status: "open",
	title: "Suspicious wire-transfer request",
	notes: null,
	shared_to_hub: 0,
	hub_event_uuid: null,
	score: null as number | null,
	summary: null as string | null,
	summary_status: null as "pending" | "ready" | "failed" | null,
	emails: [],
	observables: [],
};

function mockFetchOnce(payload: unknown) {
	const fetchMock = vi.fn().mockResolvedValue({
		ok: true,
		json: async () => payload,
	} as Response);
	vi.stubGlobal("fetch", fetchMock);
	return fetchMock;
}

// Test-only fetch mock that returns a pre-defined sequence of payloads
// for successive calls. Used by the summary-polling test (#127) where
// the first GET returns `pending` and the second returns `ready`.
function mockFetchSequence(payloads: unknown[]) {
	let i = 0;
	const fetchMock = vi.fn().mockImplementation(async () => {
		const payload = payloads[Math.min(i, payloads.length - 1)];
		i++;
		return { ok: true, json: async () => payload } as Response;
	});
	vi.stubGlobal("fetch", fetchMock);
	return fetchMock;
}

function renderCaseDetail() {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/cases/:caseId"
				element={<CaseDetailRoute />}
			/>
		</Routes>,
		{ initialEntries: ["/mailbox/m1/cases/case_abc123"] },
	);
}

describe("CaseDetailRoute (issue #126 — real per-case score)", () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("renders <ScoreRing> with the real score when data.score is present", async () => {
		mockFetchOnce({ case: { ...baseCase, score: 75 } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		// ScoreRing renders the literal "/ 100" subtitle and the numeric
		// rounded score. Confirm both, plus the absence of the empty-state
		// glyph.
		expect(screen.getByText(/\/\s*100/)).toBeInTheDocument();
		expect(screen.getByText(/^75$/)).toBeInTheDocument();
		expect(screen.queryByTestId("case-score-empty")).toBeNull();
	});

	it("renders a muted '—' in the score slot when data.score is null", async () => {
		mockFetchOnce({ case: { ...baseCase, score: null } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		// No ring → no "/ 100" subtitle. Empty-state placeholder present.
		expect(screen.queryByText(/\/\s*100/)).toBeNull();
		expect(screen.getByTestId("case-score-empty")).toBeInTheDocument();

		// And none of the legacy fabricated badges (status-derived
		// 80 / 30 from the old PR #125 placeholder) leak through.
		expect(screen.queryByText(/^80$/)).toBeNull();
		expect(screen.queryByText(/^30$/)).toBeNull();
	});

	it("still renders core case content (title, status pill, id) even without a score", async () => {
		mockFetchOnce({
			case: { ...baseCase, status: "closed-fp", score: null },
		});
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		await waitFor(() => {
			expect(screen.queryByText(/\/\s*100/)).toBeNull();
		});
		expect(screen.getByText(/case_abc123/i)).toBeInTheDocument();
	});
});

// ── AI co-pilot summary card (issue #127) ─────────────────────────
//
// The card renders only when `data.summary_status` is non-null.
// Lifecycle: pending → ready | failed. The "loading" state is the
// 'pending' card; "empty" is `summary_status === null` (card hidden);
// "error" is the 'failed' card with a refresh affordance.
describe("CaseDetailRoute — AI co-pilot summary card (#127)", () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("hides the card entirely when summary_status is null (empty state)", async () => {
		mockFetchOnce({ case: { ...baseCase, summary_status: null, summary: null } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.queryByTestId("copilot-summary-card")).toBeNull();
		expect(screen.queryByText(/Co-pilot summary/i)).toBeNull();
	});

	it("renders the loading state while summary_status is 'pending'", async () => {
		mockFetchSequence([
			{ case: { ...baseCase, summary_status: "pending", summary: null } },
		]);
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.getByTestId("copilot-summary-pending")).toBeInTheDocument();
		expect(screen.getByText(/Generating summary…/i)).toBeInTheDocument();
		expect(screen.queryByTestId("copilot-summary-ready")).toBeNull();
		expect(screen.queryByTestId("copilot-summary-failed")).toBeNull();
	});

	it("renders the summary text when summary_status is 'ready'", async () => {
		const summaryText =
			"This email pressures the recipient into a same-day wire " +
			"transfer using a spoofed CFO display name. Two suspicious " +
			"links and an urgency cue suggest a BEC attempt.";
		mockFetchOnce({
			case: { ...baseCase, summary_status: "ready", summary: summaryText },
		});
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		expect(screen.getByTestId("copilot-summary-ready")).toHaveTextContent(
			/wire transfer/i,
		);
		expect(screen.queryByTestId("copilot-summary-pending")).toBeNull();
		expect(screen.queryByTestId("copilot-summary-failed")).toBeNull();
	});

	it("renders the error state with a Refresh affordance when summary_status is 'failed'", async () => {
		mockFetchOnce({
			case: { ...baseCase, summary_status: "failed", summary: null },
		});
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		const failed = await screen.findByTestId("copilot-summary-failed");
		expect(failed).toHaveTextContent(/couldn'?t generate/i);
		expect(
			screen.getByRole("button", { name: /refresh/i }),
		).toBeInTheDocument();
	});

	it("polls while pending and switches to ready when the next fetch resolves", async () => {
		const summaryText = "Verdict-reasoning summary text from the AI.";
		const fetchMock = mockFetchSequence([
			{ case: { ...baseCase, summary_status: "pending", summary: null } },
			{ case: { ...baseCase, summary_status: "ready", summary: summaryText } },
		]);
		renderCaseDetail();

		await screen.findByTestId("copilot-summary-pending");

		await waitFor(
			() => {
				expect(screen.queryByTestId("copilot-summary-ready")).not.toBeNull();
			},
			{ timeout: 8000 },
		);
		expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2);
		expect(screen.queryByTestId("copilot-summary-pending")).toBeNull();
		expect(screen.getByTestId("copilot-summary-ready")).toHaveTextContent(
			summaryText,
		);
	});
});
