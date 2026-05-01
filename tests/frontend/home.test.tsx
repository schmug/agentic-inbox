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
	verdictMix7d: { safe: 360, suspicious: 40, phishing: 21, spam: 56, bec: 7 },
	topThreats: [
		{
			category: "phishing",
			count: 9,
			samples: [
				{ emailId: "e1", subject: "Reset your password", sender: "fake@bank.example" },
				{ emailId: "e2", subject: "Invoice attached", sender: "billing@evil.example" },
			],
		},
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
	verdictMix7d: { safe: 0, suspicious: 0, phishing: 0, spam: 0, bec: 0 },
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

	it("renders '—' for both pipeline KPIs when no scans have run", () => {
		queryState = {
			data: { ...populated, pipelineHealth: { successRate24h: null, p95Ms: null, runs24h: 0 } },
			isLoading: false,
			isError: false,
		};
		renderHome();
		// Both Pipeline success and Pipeline p95 fall back to "—".
		expect(screen.getAllByText("—")).toHaveLength(2);
	});

	it("toggles the verdict-mix card between 24h and 7d windows", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();

		// Default view is 24h: total classified count is 50+6+3+8+1 = 68.
		expect(screen.getByText(/68 classified/)).toBeInTheDocument();

		// Switch to the 7d tab — total becomes 360+40+21+56+7 = 484.
		await userEvent.click(screen.getByRole("tab", { name: "7d" }));
		expect(screen.getByText(/484 classified/)).toBeInTheDocument();

		// Switch back to 24h.
		await userEvent.click(screen.getByRole("tab", { name: "24h" }));
		expect(screen.getByText(/68 classified/)).toBeInTheDocument();
	});

	it("expands a top-threats row to reveal sample emails (#101)", async () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();

		// Samples are inside <details>, hidden until expanded — but jsdom keeps
		// them in the DOM either way. Easier to assert via the disclosure
		// element's open state than visibility heuristics.
		const phishingSummary = screen.getByText("phishing").closest("summary");
		expect(phishingSummary).toBeTruthy();
		const details = phishingSummary!.closest("details") as HTMLDetailsElement;
		expect(details.open).toBe(false);

		await userEvent.click(phishingSummary!);
		expect(details.open).toBe(true);

		// Sample rows render the subject + sender for each emailId.
		expect(screen.getByText("Reset your password")).toBeInTheDocument();
		expect(screen.getByText("fake@bank.example")).toBeInTheDocument();
		expect(screen.getByText("Invoice attached")).toBeInTheDocument();
		expect(screen.getByText("billing@evil.example")).toBeInTheDocument();
	});

	it("renders a top-threats category without samples as a count-only row", () => {
		queryState = { data: populated, isLoading: false, isError: false };
		renderHome();
		// `spam` has no samples in the populated fixture — should render
		// without a <details> wrapper (older deploys must not regress).
		const spamLabel = screen.getByText("spam");
		expect(spamLabel.closest("details")).toBeNull();
	});

	it("formats p95 latency on the org overview KPI grid", () => {
		queryState = {
			data: { ...populated, pipelineHealth: { successRate24h: 0.92, p95Ms: 1500, runs24h: 200 } },
			isLoading: false,
			isError: false,
		};
		renderHome();
		expect(screen.getByText("1.5s")).toBeInTheDocument();
	});
});
