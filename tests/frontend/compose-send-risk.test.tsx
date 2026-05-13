// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Acceptance tests for issue #263: composer send-risk UI.
 * Covers: Tier 0/1/2 button labels, data-testid attributes,
 * preflight network-failure fallback, and Tier-2 phrase confirmation.
 */

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";
import { renderWithProviders } from "./test-utils";

// ── hoisted mocks ─────────────────────────────────────────────────────────────

const feedbackInfo = vi.fn();

vi.mock("~/lib/feedback", () => ({
	useFeedback: () => ({
		info: feedbackInfo,
		error: vi.fn(),
		success: vi.fn(),
	}),
}));

vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>(
		"~/services/api",
	);
	return {
		...actual,
		default: { ...actual.default, preflightEmail: vi.fn() },
	};
});

vi.mock("~/queries/emails", () => ({
	useSendEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useSaveDraft: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useReplyToEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useForwardEmail: () => ({ mutateAsync: vi.fn().mockResolvedValue(undefined) }),
	useDeleteEmail: () => ({ mutate: vi.fn() }),
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: {
			id: "m1",
			email: "operator@internal.test",
			name: "Operator",
			settings: {},
		},
	}),
}));

// Tiptap/ProseMirror doesn't run in jsdom — replace with a no-op.
vi.mock("~/components/RichTextEditor", () => ({
	default: () => null,
}));

// ── deferred imports (after mocks are registered) ────────────────────────────

import ComposePanel from "~/components/ComposePanel";
import api from "~/services/api";

const preflightMock = api.preflightEmail as unknown as ReturnType<typeof vi.fn>;

// ── helpers ───────────────────────────────────────────────────────────────────

function renderPanel() {
	return renderWithProviders(
		<Routes>
			<Route path="/mailbox/:mailboxId" element={<ComposePanel />} />
		</Routes>,
		{ initialEntries: ["/mailbox/m1"] },
	);
}

/** Type into the "To" field and wait for the debounce to settle (≤2 s). */
async function typeToAndWaitForPreflight(
	user: ReturnType<typeof userEvent.setup>,
	address: string,
	expectedTestId: string,
) {
	await user.type(screen.getByPlaceholderText(/recipient@example.com/i), address);
	await waitFor(
		() => expect(screen.getByTestId(expectedTestId)).toBeInTheDocument(),
		{ timeout: 2000 },
	);
}

// ── test suite ────────────────────────────────────────────────────────────────

describe("Composer send-risk UI (#263)", () => {
	beforeEach(() => {
		preflightMock.mockReset();
		feedbackInfo.mockReset();
	});

	// ── Acceptance: button labels per tier ───────────────────────────────────

	describe("Send button label by tier", () => {
		it("shows 'Send' with data-testid tier0 before preflight fires", () => {
			preflightMock.mockResolvedValue({ tier: 0, reasons: [] });
			renderPanel();
			const btn = screen.getByTestId("send-button-tier0");
			expect(btn).toBeInTheDocument();
			expect(btn).toHaveTextContent("Send");
		});

		it("shows 'Send (re-auth)' with data-testid tier1 when preflight returns tier 1", async () => {
			preflightMock.mockResolvedValue({
				tier: 1,
				reasons: ["External recipient"],
			});
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			expect(screen.getByTestId("send-button-tier1")).toHaveTextContent("Send (re-auth)");
		});

		it("shows 'Send (verify)' with data-testid tier2 when preflight returns tier 2", async () => {
			preflightMock.mockResolvedValue({
				tier: 2,
				reasons: ["BEC/credential keyword"],
			});
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			expect(screen.getByTestId("send-button-tier2")).toHaveTextContent("Send (verify)");
		});
	});

	// ── Acceptance: preflight network failure does not block send ────────────

	describe("Preflight network failure fallback", () => {
		it("stays on tier0 button when preflight throws a network error", async () => {
			preflightMock.mockRejectedValue(new Error("network error"));
			const user = userEvent.setup();
			renderPanel();
			// Type the address — preflight fires but rejects; button stays tier0.
			await user.type(
				screen.getByPlaceholderText(/recipient@example.com/i),
				"vendor@external.com",
			);
			// Give the debounce time to settle then confirm tier0 persists.
			await waitFor(
				() => expect(preflightMock).toHaveBeenCalled(),
				{ timeout: 2000 },
			);
			expect(screen.getByTestId("send-button-tier0")).toBeInTheDocument();
			expect(screen.queryByTestId("send-button-tier1")).not.toBeInTheDocument();
		});
	});

	// ── Acceptance: Tier-2 confirmation phrase ───────────────────────────────

	describe("Tier-2 confirmation phrase", () => {
		it("renders the phrase input when tier is 2", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			expect(screen.getByTestId("confirm-phrase-input")).toBeInTheDocument();
		});

		it("does not render the phrase input when tier is 1", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			expect(screen.queryByTestId("confirm-phrase-input")).not.toBeInTheDocument();
		});

		it("shows an error when the form is submitted with the wrong phrase", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.type(screen.getByTestId("confirm-phrase-input"), "wrong@addr.com");
			await user.click(screen.getByTestId("send-button-tier2"));
			expect(
				screen.getByText(/type.*vendor@external\.com.*to confirm.*before sending/i),
			).toBeInTheDocument();
		});

		it("shows the step-up placeholder after the correct phrase is typed", async () => {
			preflightMock.mockResolvedValue({ tier: 2, reasons: ["BEC keyword"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier2");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.type(
				screen.getByTestId("confirm-phrase-input"),
				"vendor@external.com",
			);
			await user.click(screen.getByTestId("send-button-tier2"));
			expect(feedbackInfo).toHaveBeenCalledWith("Step-up auth not yet configured");
		});
	});

	// ── Tier-1 submit placeholder ─────────────────────────────────────────────

	describe("Tier-1 submit", () => {
		it("shows the step-up auth placeholder when tier 1 send is attempted", async () => {
			preflightMock.mockResolvedValue({ tier: 1, reasons: ["External recipient"] });
			const user = userEvent.setup();
			renderPanel();
			await typeToAndWaitForPreflight(user, "vendor@external.com", "send-button-tier1");
			await user.type(screen.getByPlaceholderText(/email subject/i), "Hello");
			await user.click(screen.getByTestId("send-button-tier1"));
			expect(feedbackInfo).toHaveBeenCalledWith("Step-up auth not yet configured");
		});
	});
});
