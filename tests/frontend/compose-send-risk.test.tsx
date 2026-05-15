// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Composer send-risk UI tests (issue #263 — slice 4 of #15).
 *
 * Covers acceptance criteria:
 *   - Send button label reflects preflight tier (Tier 0 → "Send",
 *     Tier 1 → "Send (re-auth)", Tier 2 → "Send (verify)").
 *   - Preflight network failure does not block the send flow (button stays "Send").
 *   - Tier-2 confirm requires typing the primary recipient address.
 *   - data-testid attributes on send button variants.
 *
 * URL routing in fetch mock uses `new URL(url).pathname` per the repo
 * CLAUDE.md rule against substring host checks.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: {
			id: "m1",
			email: "alice@acme.com",
			name: "Alice",
			settings: null,
		},
	}),
}));

vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue({ draft_id: "d1" }) }),
	useReplyToEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useForwardEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useDeleteEmail: () => ({ mutate: vi.fn() }),
}));

// UIStore mock factory — lets individual tests override compose options.
let uiStoreMock = {
	isComposeModalOpen: true,
	closeComposeModal: vi.fn(),
	composeOptions: {
		mode: "reply" as const,
		originalEmail: {
			id: "email1",
			sender: "bob@external.com",
			subject: "Re: Hello",
			body: "<p>test</p>",
			date: "2026-05-01T10:00:00Z",
			thread_id: "thread1",
			recipient: "alice@acme.com",
			cc: "",
		},
	},
	closePanel: vi.fn(),
	closeCompose: vi.fn(),
};

vi.mock("~/hooks/useUIStore", () => ({
	useUIStore: () => uiStoreMock,
}));

import ComposeEmail from "~/components/ComposeEmail";
import { renderWithProviders } from "./test-utils";

function renderCompose() {
	return renderWithProviders(
		<Routes>
			<Route
				path="/mailbox/:mailboxId/emails/:folder"
				element={<ComposeEmail />}
			/>
		</Routes>,
		{ initialEntries: ["/mailbox/m1/emails/inbox"] },
	);
}

function makeFetchMock(
	preflightResponse:
		| { tier: 0 | 1 | 2; reasons: string[] }
		| "network-error",
) {
	return vi.fn(async (input: string | URL | Request) => {
		const rawUrl =
			typeof input === "string"
				? input
				: input instanceof URL
					? input.href
					: input.url;
		const origin =
			typeof window !== "undefined" && window.location
				? window.location.origin
				: "http://localhost";
		const u = new URL(rawUrl, origin);

		if (u.pathname.includes("/emails/preflight")) {
			if (preflightResponse === "network-error") {
				throw new Error("Network error");
			}
			return new Response(JSON.stringify(preflightResponse), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			});
		}

		if (u.pathname.includes("/emails")) {
			return new Response(JSON.stringify({ id: "msg1", status: "sent" }), {
				status: 202,
				headers: { "Content-Type": "application/json" },
			});
		}

		throw new Error(`unhandled fetch: ${u.pathname}`);
	});
}

describe("Composer send-risk UI (#263)", () => {
	beforeEach(() => {
		uiStoreMock = {
			isComposeModalOpen: true,
			closeComposeModal: vi.fn(),
			composeOptions: {
				mode: "reply",
				originalEmail: {
					id: "email1",
					sender: "bob@external.com",
					subject: "Re: Hello",
					body: "<p>test</p>",
					date: "2026-05-01T10:00:00Z",
					thread_id: "thread1",
					recipient: "alice@acme.com",
					cc: "",
				},
			},
			closePanel: vi.fn(),
			closeCompose: vi.fn(),
		};
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("shows Send button with data-testid=send-button by default (Tier 0)", async () => {
		vi.stubGlobal("fetch", makeFetchMock({ tier: 0, reasons: [] }));
		renderCompose();

		await waitFor(() => {
			const btn = screen.getByTestId("send-button");
			expect(btn).toBeInTheDocument();
			expect(btn).toHaveTextContent("Send");
		});
	});

	it("shows Send (re-auth) with data-testid=send-button-reauth when preflight returns Tier 1", async () => {
		vi.stubGlobal(
			"fetch",
			makeFetchMock({ tier: 1, reasons: ["External recipient(s): bob@external.com"] }),
		);
		renderCompose();

		await waitFor(() => {
			const btn = screen.getByTestId("send-button-reauth");
			expect(btn).toBeInTheDocument();
			expect(btn).toHaveTextContent("Send (re-auth)");
		});
	});

	it("shows Send (verify) with data-testid=send-button-verify and phrase input when preflight returns Tier 2", async () => {
		vi.stubGlobal(
			"fetch",
			makeFetchMock({ tier: 2, reasons: ['BEC/credential keyword: "wire transfer"'] }),
		);
		renderCompose();

		await waitFor(() => {
			expect(screen.getByTestId("send-button-verify")).toBeInTheDocument();
			expect(screen.getByTestId("send-button-verify")).toHaveTextContent("Send (verify)");
			expect(screen.getByTestId("send-verify-phrase-input")).toBeInTheDocument();
		});
	});

	it("preflight network failure leaves button as Send (Tier 0 default)", async () => {
		vi.stubGlobal("fetch", makeFetchMock("network-error"));
		renderCompose();

		// Give the failed preflight call time to settle.
		await new Promise((r) => setTimeout(r, 100));

		expect(screen.getByTestId("send-button")).toBeInTheDocument();
		expect(screen.getByTestId("send-button")).toHaveTextContent("Send");
	});

	it("Tier-2 click without phrase shows validation error", async () => {
		vi.stubGlobal(
			"fetch",
			makeFetchMock({ tier: 2, reasons: ['BEC/credential keyword: "wire transfer"'] }),
		);
		renderCompose();

		await waitFor(() => screen.getByTestId("send-button-verify"));

		await userEvent.click(screen.getByTestId("send-button-verify"));

		// Use selector:'p' to distinguish the Banner's <p> from the phrase input <span> label —
		// both contain the phrase text but only the error banner wraps it in a <p>.
		await waitFor(() => {
			expect(
				screen.getByText(/to confirm before sending\./i, { selector: "p" }),
			).toBeInTheDocument();
		});
	});

	it("Tier-2 click with correct phrase shows step-up placeholder", async () => {
		vi.stubGlobal(
			"fetch",
			makeFetchMock({ tier: 2, reasons: ['BEC/credential keyword: "wire transfer"'] }),
		);
		renderCompose();

		await waitFor(() => screen.getByTestId("send-verify-phrase-input"));

		await userEvent.type(
			screen.getByTestId("send-verify-phrase-input"),
			"bob@external.com",
		);
		await userEvent.click(screen.getByTestId("send-button-verify"));

		// The kumo toast for "Step-up auth not yet configured" must appear somewhere in the DOM.
		await waitFor(() => {
			expect(
				screen.queryAllByText(/step-up auth not yet configured/i).length,
			).toBeGreaterThan(0);
		});
	});

	it("Tier-1 click shows step-up placeholder without phrase input", async () => {
		vi.stubGlobal(
			"fetch",
			makeFetchMock({ tier: 1, reasons: ["External recipient(s): bob@external.com"] }),
		);
		renderCompose();

		await waitFor(() => screen.getByTestId("send-button-reauth"));
		expect(screen.queryByTestId("send-verify-phrase-input")).toBeNull();

		await userEvent.click(screen.getByTestId("send-button-reauth"));

		await waitFor(() => {
			expect(
				screen.queryAllByText(/step-up auth not yet configured/i).length,
			).toBeGreaterThan(0);
		});
	});
});
