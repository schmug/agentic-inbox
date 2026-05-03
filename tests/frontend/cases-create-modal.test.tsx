// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Frontend tests for the manual-case create dialog (issue #190).
 *
 * Covers the acceptance criteria:
 *   - Clicking "+ Manual case" opens the dialog.
 *   - Submit a valid case → POST hits the worker endpoint, dialog
 *     closes, the cases list re-fetches, and the new case appears.
 *   - Submit an invalid case → field-level error renders inline,
 *     dialog stays open.
 *
 * Mock fetch dispatcher matches by parsed URL (`new URL(url).hostname`)
 * per the repo CLAUDE.md "URL host checks in test mocks must parse, not
 * substring" rule that gates CodeQL.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

import CasesRoute from "~/routes/cases";
import { renderWithProviders } from "./test-utils";

interface CaseRow {
	id: string;
	created_at: string;
	updated_at: string;
	status: string;
	title: string;
	shared_to_hub: number;
}

const baseCase = (over: Partial<CaseRow> = {}): CaseRow => ({
	id: "case_initial",
	created_at: "2026-04-29T11:00:00Z",
	updated_at: "2026-04-29T11:30:00Z",
	status: "open",
	title: "Initial open case",
	shared_to_hub: 0,
	...over,
});

/**
 * Build a fetch mock keyed on the request's parsed URL + method. Tests
 * mutate `state.cases` and `state.lastPostBody` via the returned helpers.
 *
 * jsdom requires absolute URLs for `new URL(...)`; the route fetches
 * relative paths, so we construct against `window.location.origin`.
 */
function installFetchMock() {
	const state: {
		cases: CaseRow[];
		lastPostBody: unknown;
		nextPostResponse:
			| { kind: "ok"; id: string }
			| { kind: "validation"; fieldErrors: Record<string, string[]> }
			| { kind: "server-error" };
	} = {
		cases: [baseCase()],
		lastPostBody: null,
		nextPostResponse: { kind: "ok", id: "case_new" },
	};

	const fetchMock = vi.fn(
		async (input: string | URL | Request, init?: RequestInit) => {
			const rawUrl =
				typeof input === "string"
					? input
					: input instanceof URL
						? input.href
						: input.url;
			// Resolve relative URLs against the test origin so URL.parse works.
			const origin =
				typeof window !== "undefined" && window.location
					? window.location.origin
					: "http://localhost";
			const u = new URL(rawUrl, origin);
			const method = (init?.method ?? "GET").toUpperCase();

			// Only the local app origin is in play; assert it matches so a
			// mistakenly-absolute URL doesn't slip past the dispatcher.
			if (u.hostname !== new URL(origin).hostname) {
				throw new Error(`unexpected hostname: ${u.hostname}`);
			}

			// `GET /api/v1/mailboxes/:id/cases[?status=…]`
			if (
				method === "GET" &&
				u.pathname.startsWith("/api/v1/mailboxes/") &&
				u.pathname.endsWith("/cases")
			) {
				const status = u.searchParams.get("status");
				const filtered = status
					? state.cases.filter((c) => c.status === status)
					: state.cases;
				return new Response(JSON.stringify({ cases: filtered }), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				});
			}

			// `POST /api/v1/mailboxes/:id/cases`
			if (
				method === "POST" &&
				u.pathname.startsWith("/api/v1/mailboxes/") &&
				u.pathname.endsWith("/cases")
			) {
				state.lastPostBody = init?.body
					? JSON.parse(init.body as string)
					: null;
				const next = state.nextPostResponse;
				if (next.kind === "ok") {
					// Insert the new case so the post-create refetch surfaces it.
					state.cases = [
						{
							id: next.id,
							created_at: "2026-05-03T12:00:00Z",
							updated_at: "2026-05-03T12:00:00Z",
							status: "open",
							title:
								(state.lastPostBody as { title?: string } | null)?.title ??
								"(no title)",
							shared_to_hub: 0,
						},
						...state.cases,
					];
					return new Response(JSON.stringify({ id: next.id }), {
						status: 201,
						headers: { "Content-Type": "application/json" },
					});
				}
				if (next.kind === "validation") {
					return new Response(
						JSON.stringify({
							error: {
								formErrors: [],
								fieldErrors: next.fieldErrors,
							},
						}),
						{
							status: 400,
							headers: { "Content-Type": "application/json" },
						},
					);
				}
				return new Response(JSON.stringify({ error: "boom" }), {
					status: 500,
					headers: { "Content-Type": "application/json" },
				});
			}

			throw new Error(`unhandled fetch: ${method} ${u.pathname}`);
		},
	);

	vi.stubGlobal("fetch", fetchMock);
	return { state, fetchMock };
}

function renderCases() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId/cases" element={<CasesRoute />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1/cases"] },
	);
}

describe("CasesRoute manual-case dialog (issue #190)", () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.clearAllMocks();
	});

	it("clicking '+ Manual case' opens the dialog with title/notes/email-id fields", async () => {
		installFetchMock();
		renderCases();

		// Initial list rendered. The route renders desktop + mobile lists
		// simultaneously, so the title appears twice — assert on the
		// count rather than `findByText`.
		const initial = await screen.findAllByText(/Initial open case/i);
		expect(initial.length).toBeGreaterThan(0);

		// Dialog not yet in the DOM. Match by the modal's unique title;
		// kumo's <Toasty> region also has role="dialog", so a generic
		// role query is too broad here.
		expect(screen.queryByText(/create manual case/i)).toBeNull();

		await userEvent.click(
			screen.getByRole("button", { name: /manual case/i }),
		);

		// Dialog open with the schema-derived fields.
		expect(
			await screen.findByText(/create manual case/i),
		).toBeInTheDocument();
		expect(screen.getByLabelText(/^title$/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/^notes$/i)).toBeInTheDocument();
		expect(screen.getByLabelText(/linked email id/i)).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: /^create case$/i }),
		).toBeInTheDocument();
		expect(
			screen.getByRole("button", { name: /^cancel$/i }),
		).toBeInTheDocument();
	});

	it("submitting a valid case POSTs, closes the dialog, and the new case shows in the list", async () => {
		const { state } = installFetchMock();
		renderCases();

		// Wait for initial render.
		await screen.findAllByText(/Initial open case/i);

		// Open dialog.
		await userEvent.click(
			screen.getByRole("button", { name: /manual case/i }),
		);
		await screen.findByText(/create manual case/i);

		// Fill and submit.
		await userEvent.type(
			screen.getByLabelText(/^title$/i),
			"Suspicious gift-card scam",
		);
		await userEvent.type(
			screen.getByLabelText(/^notes$/i),
			"Forwarded by user@example.com",
		);
		await userEvent.click(
			screen.getByRole("button", { name: /^create case$/i }),
		);

		// Worker received the right body. `notes` populated; `emailId`
		// omitted because it was blank.
		await waitFor(() => {
			expect(state.lastPostBody).toEqual({
				title: "Suspicious gift-card scam",
				notes: "Forwarded by user@example.com",
			});
		});

		// Dialog closed. Note: kumo's <Toasty> renders each toast inside a
		// `role="dialog"` element, so we can't query the modal generically
		// — we check for the modal's title text instead, which is unique
		// to the manual-case dialog.
		await waitFor(() => {
			expect(screen.queryByText(/create manual case/i)).toBeNull();
		});

		// List refetched and the new case appears (desktop + mobile copies).
		const matches = await screen.findAllByText(/Suspicious gift-card scam/i);
		expect(matches.length).toBeGreaterThan(0);
	});

	it("400 with field errors renders inline error text and keeps the dialog open", async () => {
		const { state } = installFetchMock();
		state.nextPostResponse = {
			kind: "validation",
			fieldErrors: {
				title: ["String must contain at most 500 character(s)"],
			},
		};
		renderCases();

		await screen.findAllByText(/Initial open case/i);
		await userEvent.click(
			screen.getByRole("button", { name: /manual case/i }),
		);
		await screen.findByText(/create manual case/i);

		// Type something that the client allows through but the worker
		// rejects (mocked above as a max-length error). The point of this
		// test is the error-rendering path, not the client-side guards.
		await userEvent.type(
			screen.getByLabelText(/^title$/i),
			"a too-long title (mocked rejection)",
		);
		await userEvent.click(
			screen.getByRole("button", { name: /^create case$/i }),
		);

		// Inline error rendered (NOT a generic toast).
		expect(
			await screen.findByText(/at most 500 character/i),
		).toBeInTheDocument();

		// Dialog still open — user can correct and retry. The "Create
		// case" submit button only exists inside the modal, so its
		// presence is a stronger signal than just the title text.
		expect(
			screen.getByRole("button", { name: /^create case$/i }),
		).toBeInTheDocument();
	});
});
