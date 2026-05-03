// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.
//
// Regression test for #186 — "Ask co-pilot" no-op on org-level routes.
//
// The Shell topbar's "Ask co-pilot" button used to render unconditionally on
// every page, but the agent panel only mounts inside `/mailbox/:mailboxId/*`
// routes (mailbox.tsx is the only caller passing `rightPanel={<AgentSidebar
// />}`). Clicking the button on `/`, `/settings`, `/mailboxes`, `/domains`,
// or `/domains/:domain` toggled internal state but produced no visible change.
//
// Until an org-scope co-pilot ships, the trigger must be `disabled` (with a
// tooltip explaining why) when the current route has no `mailboxId`. The
// per-mailbox route still opens the panel.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: { id: "m1", email: "alice@acme.com", name: "Alice" },
	}),
	useMailboxes: () => ({
		data: [{ id: "m1", email: "alice@acme.com", name: "Alice" }],
	}),
}));

vi.mock("~/queries/dashboard", () => ({
	useDashboardSummary: () => ({
		data: undefined,
		isLoading: false,
		isError: false,
	}),
}));

vi.mock("~/queries/domains", () => ({
	useDomainStats: () => ({
		data: undefined,
		isLoading: false,
		isError: false,
	}),
}));

import Shell from "~/components/phishsoc/Shell";
import { useUIStore } from "~/hooks/useUIStore";
import { renderWithProviders } from "./test-utils";

const RIGHT_PANEL_TEST_ID = "agent-panel-content";

function RightPanelStub() {
	return <div data-testid={RIGHT_PANEL_TEST_ID}>agent panel content</div>;
}

// Renders Shell mounted at the route patterns the app actually uses, so
// `useParams<{ mailboxId }>()` resolves the same way it does in production.
// Org-level routes pass no `rightPanel`; mailbox-level routes do.
function renderAtRoute(initialEntry: string) {
	return renderWithProviders(
		<Routes>
			<Route
				path="/"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/settings"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/mailboxes"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/domains"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/domains/:domain"
				element={
					<Shell>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
			<Route
				path="/mailbox/:mailboxId/*"
				element={
					<Shell rightPanel={<RightPanelStub />}>
						<div data-testid="main-content">main</div>
					</Shell>
				}
			/>
		</Routes>,
		{ initialEntries: [initialEntry] },
	);
}

beforeEach(() => {
	useUIStore.setState({ isAgentPanelOpen: false });
	window.matchMedia = vi.fn().mockImplementation((query: string) => ({
		matches: false,
		media: query,
		onchange: null,
		addListener: vi.fn(),
		removeListener: vi.fn(),
		addEventListener: vi.fn(),
		removeEventListener: vi.fn(),
		dispatchEvent: vi.fn(),
	}));
});

afterEach(() => {
	useUIStore.setState({ isAgentPanelOpen: false });
});

describe("Shell 'Ask co-pilot' button — org-level routes (#186)", () => {
	const orgRoutes: Array<[label: string, path: string]> = [
		["org overview /", "/"],
		["org settings /settings", "/settings"],
		["mailboxes list /mailboxes", "/mailboxes"],
		["domains list /domains", "/domains"],
		["domain detail /domains/:domain", "/domains/example.com"],
	];

	for (const [label, path] of orgRoutes) {
		it(`is disabled with a 'pick a mailbox' tooltip on ${label}`, () => {
			renderAtRoute(path);
			const trigger = screen.getByRole("button", {
				name: /ask co-?pilot/i,
			});
			expect(trigger).toBeDisabled();
			expect(trigger).toHaveAttribute(
				"title",
				"Pick a mailbox to chat with the agent",
			);
			// Without a mailbox, aria-expanded shouldn't advertise an
			// open/closed panel state — the panel can't open here at all.
			expect(trigger).not.toHaveAttribute("aria-expanded");
		});

		it(`clicking it on ${label} does not toggle the agent panel state`, async () => {
			const user = userEvent.setup();
			renderAtRoute(path);
			const trigger = screen.getByRole("button", {
				name: /ask co-?pilot/i,
			});
			expect(useUIStore.getState().isAgentPanelOpen).toBe(false);
			// userEvent.click respects `disabled` and skips the click,
			// so the store stays untouched — exactly the behavior we want.
			await user.click(trigger);
			expect(useUIStore.getState().isAgentPanelOpen).toBe(false);
			expect(screen.queryByTestId(RIGHT_PANEL_TEST_ID)).not.toBeInTheDocument();
		});
	}
});

describe("Shell 'Ask co-pilot' button — mailbox-level route still works", () => {
	it("is enabled on /mailbox/:mailboxId/* and opens the panel on click", async () => {
		const user = userEvent.setup();
		renderAtRoute("/mailbox/m1/dashboard");
		const trigger = screen.getByRole("button", { name: /ask co-?pilot/i });
		expect(trigger).not.toBeDisabled();
		expect(trigger).not.toHaveAttribute("title");
		expect(trigger).toHaveAttribute("aria-expanded", "false");
		await user.click(trigger);
		expect(useUIStore.getState().isAgentPanelOpen).toBe(true);
		expect(screen.getByTestId(RIGHT_PANEL_TEST_ID)).toBeInTheDocument();
		expect(trigger).toHaveAttribute("aria-expanded", "true");
	});
});
