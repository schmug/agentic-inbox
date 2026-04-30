// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import type { OrgOverview } from "~/types";

const refetch = vi.fn();
let queryState: {
	data: OrgOverview | undefined;
	isLoading: boolean;
	isError: boolean;
};

vi.mock("~/queries/org", () => ({
	useOrgOverview: () => ({ ...queryState, refetch }),
}));

// The org-overview home page renders an "N mailboxes" hint sourced from
// `useMailboxes`. Provide a stable empty list so renders don't fan out to
// the real fetcher. `useMailbox` is also stubbed because Shell consumes it.
vi.mock("~/queries/mailboxes", () => ({
	useMailboxes: () => ({ data: [], refetch: vi.fn(), isFetched: true }),
	useMailbox: () => ({ data: undefined }),
}));

// Shell renders the per-mailbox dashboard summary into the pipeline pill;
// at "/" mailboxId is undefined and the query is disabled, but the hook is
// still imported, so stub it to keep the test independent of TanStack
// internals.
vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => ({ data: undefined }),
}));

// `useAutoProvisionMailboxes` reads config + mailboxes and may fire a POST
// when EMAIL_ADDRESSES is set. The org-overview test doesn't exercise that
// path, so stub it out to keep the surface focused.
vi.mock("~/hooks/useAutoProvisionMailboxes", () => ({
	useAutoProvisionMailboxes: () => undefined,
}));

import HomeRoute from "~/routes/home";
import { renderWithProviders } from "./test-utils";

function renderHome() {
	return renderWithProviders(
		<Routes>
			<Route path="/" element={<HomeRoute />} />
			<Route path="/mailboxes" element={<div>Mailboxes page</div>} />
		</Routes>,
		{ initialEntries: ["/"] },
	);
}

const populated: OrgOverview = {
	now: "2026-04-29T12:00:00Z",
	threatsBlocked24h: 12,
	threatsBlocked7d: 84,
	openCasesTotal: 5,
	mailboxesCount: 3,
	domainsCount: 2,
	hubContributions24h: 4,
	verdictMix: { safe: 50, suspicious: 6, phishing: 3, spam: 8, bec: 1 },
	topThreats: [
		{ category: "phishing", count: 9 },
		{ category: "spam", count: 4 },
	],
	pipelineHealth: { successRate24h: 0.92, p95Ms: null, runs24h: 200 },
};

const empty: OrgOverview = {
	now: "2026-04-29T12:00:00Z",
	threatsBlocked24h: 0,
	threatsBlocked7d: 0,
	openCasesTotal: 0,
	mailboxesCount: 0,
	domainsCount: 0,
	hubContributions24h: 0,
	verdictMix: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
	topThreats: [],
	pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 },
};

describe("HomeRoute (org overview)", () => {
	beforeEach(() => {
		refetch.mockReset();
	});

	it("renders the loader while the query is pending", () => {
		queryState = { data: undefined, isLoading: true, isError: false };
		renderHome();
		expect(screen.getByText(/across the fleet/i)).toBeInTheDocument();
		expect(screen.queryByText(/threats blocked · 24h/i)).not.toBeInTheDocument();
	});

	it("renders error UI with a working retry when the query fails", async () => {
		queryState = { data: undefined, isLoading: false, isError: true };
		renderHome();
		expect(screen.getByText(/couldn't load the org overview/i)).toBeInTheDocument();
		await userEvent.click(screen.getByRole("button", { name: /retry/i }));
		expect(refetch).toHaveBeenCalledTimes(1);
	});

	it("renders KPIs, verdict mix, and top threats when data is present", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();
		expect(screen.getByText(/threats blocked · 24h/i)).toBeInTheDocument();
		expect(screen.getByText("12")).toBeInTheDocument(); // threatsBlocked24h
		expect(screen.getByText("84")).toBeInTheDocument(); // threatsBlocked7d
		expect(screen.getByText("92%")).toBeInTheDocument(); // pipelineSuccess
		expect(screen.getByText("3 mailboxes · 2 domains")).toBeInTheDocument();
		expect(screen.getByText(/top threats/i)).toBeInTheDocument();
		// "phishing" appears as both a verdict-mix label and a top-threats
		// category, so assert on count rather than presence.
		expect(screen.getAllByText(/phishing/i).length).toBeGreaterThanOrEqual(2);
		expect(screen.getByText("9")).toBeInTheDocument(); // top-threats count
	});

	it("shows an empty-state CTA linking to /mailboxes when zero mailboxes", () => {
		queryState = { data: empty, isLoading: false, isError: false };
		renderHome();
		expect(screen.getByText(/no mailboxes yet/i)).toBeInTheDocument();
		const cta = screen.getByRole("link", { name: /go to mailboxes/i });
		expect(cta).toHaveAttribute("href", "/mailboxes");
	});

	it("renders '—' for pipelineSuccess when no scans have run", () => {
		queryState = {
			data: { ...populated, pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 } },
			isLoading: false,
			isError: false,
		};
		renderHome();
		expect(screen.getByText("—")).toBeInTheDocument();
	});
});
