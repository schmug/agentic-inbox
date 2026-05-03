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
