// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { DashboardSummary } from "~/types";
import { shellDashboardMock } from "./shell-mocks";

const refetch = vi.fn();
let queryState: {
	data: DashboardSummary | undefined;
	isLoading: boolean;
	isError: boolean;
};

// `DashboardRoute` consumes `useDashboardSummary` directly. The route is
// rendered in isolation here (the parent `mailbox.tsx` layout that mounts
// Shell isn't in the tree), so only the dashboard factory is needed — the
// other Shell factories aren't load-bearing for this file. Using the shared
// factory keeps the override pattern aligned with the Shell-rendering tests.
vi.mock("~/queries/dashboard", () =>
	shellDashboardMock({
		useDashboardSummary: () => ({ ...queryState, refetch }),
	}),
);

import DashboardRoute from "~/routes/dashboard";
import { renderWithProviders } from "./test-utils";

function renderDashboard() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId/dashboard" element={<DashboardRoute />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1/dashboard"] },
	);
}

const populated: DashboardSummary = {
	now: "2026-04-29T12:00:00Z",
	threatsBlocked: 3,
	openCases: 7,
	hubContributions: 2,
	corroboration: 4,
	pipelineSuccess: 0.92,
	p95Ms: 1500,
	threatPressure: [0, 1, 0, 2, 1, 0, 3, 0, 0, 1, 0, 0],
	recentCases: [
		{ id: "c1", title: "Suspicious wire request", status: "open", updated_at: "2026-04-29T11:00:00Z" },
		{ id: "c2", title: "Credential phish", status: "closed-tp", updated_at: "2026-04-29T08:00:00Z" },
	],
};

describe("DashboardRoute", () => {
	beforeEach(() => {
		refetch.mockReset();
	});

	it("renders the loader while the query is pending", () => {
		queryState = { data: undefined, isLoading: true, isError: false };
		renderDashboard();
		// The kumo Loader doesn't expose role=progressbar reliably, so assert by
		// the presence of the header copy + absence of the KPI labels.
		expect(screen.getByText(/good morning/i)).toBeInTheDocument();
		expect(screen.queryByText(/threats blocked · 24h/i)).not.toBeInTheDocument();
	});

	it("renders error UI with a working retry when the query fails", async () => {
		queryState = { data: undefined, isLoading: false, isError: true };
		renderDashboard();
		expect(screen.getByText(/couldn't load the dashboard/i)).toBeInTheDocument();
		await userEvent.click(screen.getByRole("button", { name: /retry/i }));
		expect(refetch).toHaveBeenCalledTimes(1);
	});

	it("renders KPI values and recent cases when data is present", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDashboard();
		expect(screen.getByText(/threats blocked · 24h/i)).toBeInTheDocument();
		expect(screen.getByText("3")).toBeInTheDocument();
		expect(screen.getByText("7")).toBeInTheDocument();
		expect(screen.getByText("92%")).toBeInTheDocument();
		// p95Ms 1500 → formatLatency renders "1.5s" (≥1000ms, <10s ⇒ one decimal).
		// 1500 is exactly representable in IEEE-754 so toFixed is unambiguous;
		// values like 1450 would render "1.4s" because (1.45).toFixed(1) rounds
		// down on the underlying 1.4499999… binary representation.
		expect(screen.getByText("1.5s")).toBeInTheDocument();
		expect(screen.getByText("2")).toBeInTheDocument();
		// Hub corroboration card (#72) renders alongside Hub contributions.
		expect(screen.getByText(/hub corroboration · 24h/i)).toBeInTheDocument();
		expect(screen.getByText("4")).toBeInTheDocument();
		expect(screen.getByText(/suspicious wire request/i)).toBeInTheDocument();
		expect(screen.getByText(/credential phish/i)).toBeInTheDocument();
	});

	it("renders '—' for pipelineSuccess, p95, and corroboration when null, and 'No cases yet.' when empty", () => {
		queryState = {
			data: {
				now: populated.now,
				threatsBlocked: 0,
				openCases: 0,
				hubContributions: 0,
				corroboration: null,
				pipelineSuccess: null,
				p95Ms: null,
				threatPressure: new Array(12).fill(0),
				recentCases: [],
			},
			isLoading: false,
			isError: false,
		};
		renderDashboard();
		// Three KPI cards (pipeline-success, pipeline-p95, hub-corroboration)
		// render the "—" placeholder when their respective values are null.
		expect(screen.getAllByText("—")).toHaveLength(3);
		expect(screen.getByText(/no cases yet/i)).toBeInTheDocument();
	});

	it("renders sibling KPI cards unaffected when corroboration is null", () => {
		// Hub outage shouldn't blank the rest of the dashboard — the hub
		// contributions card and the threats-blocked count stay populated.
		queryState = {
			data: { ...populated, corroboration: null },
			isLoading: false,
			isError: false,
		};
		renderDashboard();
		expect(screen.getByText(/hub contributions · 24h/i)).toBeInTheDocument();
		expect(screen.getByText("2")).toBeInTheDocument(); // hubContributions
		expect(screen.getByText("3")).toBeInTheDocument(); // threatsBlocked
		expect(screen.getByText(/hub corroboration · 24h/i)).toBeInTheDocument();
		// Exactly one "—" — the corroboration card.
		expect(screen.getAllByText("—")).toHaveLength(1);
	});

	it("links each recent case to /mailbox/:id/cases/:caseId", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderDashboard();
		const link = screen.getByRole("link", { name: /suspicious wire request/i });
		expect(link).toHaveAttribute("href", "/mailbox/m1/cases/c1");
	});
});
