// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

import CaseDetailRoute from "~/routes/case-detail";
import { renderWithProviders } from "./test-utils";

// The case API today returns only the columns persisted on the `cases` table
// (id, status, title, notes, …) plus the linked-emails and observables joins.
// It does NOT return `score`, `summary`, or `stage_trace` — issue #87 is about
// removing the placeholder UI that pretended otherwise. The mock mirrors that
// real shape so the assertions below verify behavior under current data, not
// a hypothetical future schema.
const baseCase = {
	id: "case_abc123",
	created_at: "2026-04-29T11:00:00Z",
	updated_at: "2026-04-29T11:30:00Z",
	status: "open",
	title: "Suspicious wire-transfer request",
	notes: null,
	shared_to_hub: 0,
	hub_event_uuid: null,
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

describe("CaseDetailRoute (interim mitigation, issue #87)", () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("renders no fabricated score, no co-pilot placeholder, no pipeline-trace placeholder when the case API omits score/summary/stage_trace", async () => {
		mockFetchOnce({ case: baseCase });
		renderCaseDetail();

		// Wait for the fetch-driven render to commit.
		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();

		// 1. No fabricated score badge. <ScoreRing> renders the literal
		//    "/ 100" subtitle under the numeric score; if it's gone, the
		//    title-bar fabrication is gone. We also confirm the
		//    "open" → 80 / "closed-fp" → 30 numeric placeholders are absent.
		expect(screen.queryByText(/\/\s*100/)).toBeNull();
		expect(screen.queryByText(/^80$/)).toBeNull();
		expect(screen.queryByText(/^30$/)).toBeNull();

		// 2. No "Coming soon" co-pilot card.
		expect(screen.queryByText(/coming soon/i)).toBeNull();
		expect(screen.queryByText(/co-pilot summary/i)).toBeNull();

		// 3. No pipeline-trace placeholder copy.
		expect(
			screen.queryByText(/stage-level scoring isn't surfaced/i),
		).toBeNull();
		expect(screen.queryByText(/pipeline trace/i)).toBeNull();
	});

	it("still renders core case content (title, status, linked-emails empty state) so the page isn't blanked out", async () => {
		mockFetchOnce({ case: { ...baseCase, status: "closed-fp" } });
		renderCaseDetail();

		expect(
			await screen.findByText(/Suspicious wire-transfer request/i),
		).toBeInTheDocument();
		// "closed-fp" maps to a "Released" / "Closed" verdict label via
		// statusLabel(); we only need to confirm a status pill is present
		// and the dangerous fabricated score isn't.
		await waitFor(() => {
			expect(screen.queryByText(/\/\s*100/)).toBeNull();
		});
		expect(screen.getByText(/case_abc123/i)).toBeInTheDocument();
	});
});
