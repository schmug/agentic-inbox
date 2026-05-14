// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for the send-risk UI behaviour wired in issue #263 (slice 4 of #15).
 *
 * Acceptance criteria tested:
 *   1. Preflight success → hook exposes correct sendButtonLabel / sendButtonTestId
 *      for each tier (Tier 0 = "Send", Tier 1 = "Send (re-auth)", Tier 2 = "Send (verify)")
 *   2. Preflight network failure → Tier 0 / send not blocked
 *   3. Tier-2 typed-confirmation gating: tier2Confirmed is false until the
 *      primaryRecipient address is typed exactly into tier2Input
 *
 * Tests for the hook live here (not component render tests) because
 * `useComposeForm` has deep dependencies (mailbox queries, UIStore, router
 * params) that would require a full Shell mock. Testing the hook directly via
 * `renderHook` with module-level vi.mock keeps the surface focused.
 */

import { renderHook, act, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

// ── stable mocks for non-preflight hooks ─────────────────────────────────────

const mockFeedback = { success: vi.fn(), error: vi.fn(), info: vi.fn() };
vi.mock("~/lib/feedback", () => ({
	useFeedback: () => mockFeedback,
}));

vi.mock("react-router", () => ({
	useParams: () => ({}),
}));

const mockComposeOptions = {
	mode: "compose" as const,
	draftEmail: null,
	originalEmail: null,
};
vi.mock("~/hooks/useUIStore", () => ({
	useUIStore: () => ({
		composeOptions: mockComposeOptions,
		closePanel: vi.fn(),
		closeCompose: vi.fn(),
	}),
}));

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: {
			id: "ops@example.com",
			email: "ops@example.com",
			name: "Ops",
			settings: {},
		},
	}),
}));

const mockSendEmail = { mutateAsync: vi.fn() };
const mockSaveDraft = { mutateAsync: vi.fn() };
const mockReply = { mutateAsync: vi.fn() };
const mockForward = { mutateAsync: vi.fn() };
const mockDeleteEmail = { mutate: vi.fn() };

// preflightMutateAsync is controlled per-test.
let preflightMutateAsync = vi.fn();

vi.mock("~/queries/emails", async (orig) => {
	const original = await orig<typeof import("~/queries/emails")>();
	return {
		...original,
		useSendEmail: () => mockSendEmail,
		useSaveDraft: () => mockSaveDraft,
		useReplyToEmail: () => mockReply,
		useForwardEmail: () => mockForward,
		useDeleteEmail: () => mockDeleteEmail,
		usePreflightEmail: () => ({ mutateAsync: preflightMutateAsync }),
	};
});

import { useComposeForm } from "~/hooks/useComposeForm";

// ── wrapper with React Query provider ────────────────────────────────────────

function makeWrapper() {
	const qc = new QueryClient({
		defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
	});
	return function Wrapper({ children }: { children: ReactNode }) {
		return (
			<QueryClientProvider client={qc}>{children}</QueryClientProvider>
		);
	};
}

// ── Tier 0 ───────────────────────────────────────────────────────────────────

describe("useComposeForm — Tier 0 preflight", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		preflightMutateAsync = vi.fn().mockResolvedValue({ tier: 0, reasons: [] });
	});

	it("defaults to Tier 0 before preflight resolves", () => {
		// Hang preflight indefinitely so we can observe the default.
		preflightMutateAsync = vi.fn().mockReturnValue(new Promise(() => {}));
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		expect(result.current.sendButtonLabel).toBe("Send");
		expect(result.current.sendButtonTestId).toBe("send-button-tier0");
	});

	it("stays Tier 0 after preflight returns tier=0", async () => {
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(preflightMutateAsync).toHaveBeenCalledTimes(1));
		expect(result.current.sendButtonLabel).toBe("Send");
		expect(result.current.sendButtonTestId).toBe("send-button-tier0");
	});
});

// ── Tier 1 ───────────────────────────────────────────────────────────────────

describe("useComposeForm — Tier 1 preflight", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		preflightMutateAsync = vi.fn().mockResolvedValue({
			tier: 1,
			reasons: ["External recipient"],
		});
	});

	it("shows 'Send (re-auth)' label and tier1 testid after preflight returns tier=1", async () => {
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(result.current.sendButtonLabel).toBe("Send (re-auth)"));
		expect(result.current.sendButtonTestId).toBe("send-button-tier1");
	});
});

// ── Tier 2 ───────────────────────────────────────────────────────────────────

describe("useComposeForm — Tier 2 preflight", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		preflightMutateAsync = vi.fn().mockResolvedValue({
			tier: 2,
			reasons: ["BEC keyword detected"],
		});
	});

	it("shows 'Send (verify)' label and tier2 testid after preflight returns tier=2", async () => {
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(result.current.sendButtonLabel).toBe("Send (verify)"));
		expect(result.current.sendButtonTestId).toBe("send-button-tier2");
	});

	it("tier2Confirmed is false when tier2Input is empty", async () => {
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(result.current.sendButtonLabel).toBe("Send (verify)"));
		// Set a primary recipient
		act(() => { result.current.setTo("target@evil.example"); });
		expect(result.current.tier2Confirmed).toBe(false);
	});

	it("tier2Confirmed is false when tier2Input does not match primary recipient", async () => {
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(result.current.sendButtonLabel).toBe("Send (verify)"));
		act(() => {
			result.current.setTo("target@evil.example");
			result.current.setTier2Input("wrong@example.com");
		});
		expect(result.current.tier2Confirmed).toBe(false);
	});

	it("tier2Confirmed is true when tier2Input matches primary recipient (case-insensitive)", async () => {
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(result.current.sendButtonLabel).toBe("Send (verify)"));
		act(() => {
			result.current.setTo("Target@Evil.example");
			result.current.setTier2Input("target@evil.example");
		});
		expect(result.current.tier2Confirmed).toBe(true);
	});
});

// ── Preflight network failure ─────────────────────────────────────────────────

describe("useComposeForm — preflight network failure", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		preflightMutateAsync = vi.fn().mockRejectedValue(new Error("Network error"));
	});

	it("defaults to Tier 0 when preflight throws a network error", async () => {
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		// Wait for preflight to have been called and the error handled.
		await waitFor(() => expect(preflightMutateAsync).toHaveBeenCalledTimes(1));
		// After the rejection, the hook should have fallen back to Tier 0.
		await waitFor(() => expect(result.current.preflight.tier).toBe(0));
		expect(result.current.sendButtonLabel).toBe("Send");
		expect(result.current.sendButtonTestId).toBe("send-button-tier0");
		// A warning must have been emitted.
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("[preflight]"),
			expect.any(Error),
		);
		warnSpy.mockRestore();
	});

	it("send button is not blocked after preflight network failure", async () => {
		vi.spyOn(console, "warn").mockImplementation(() => {});
		const { result } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(preflightMutateAsync).toHaveBeenCalledTimes(1));
		await waitFor(() => expect(result.current.preflight.tier).toBe(0));
		// Tier 0 → send button is enabled (not blocked).
		expect(result.current.sendButtonTestId).toBe("send-button-tier0");
	});
});

// ── preflight fires only once per compose session ─────────────────────────────

describe("useComposeForm — preflight fires once per session", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		preflightMutateAsync = vi.fn().mockResolvedValue({ tier: 0, reasons: [] });
	});

	it("calls preflight exactly once on mount (not on re-renders)", async () => {
		const { result, rerender } = renderHook(
			() => useComposeForm("ops@example.com"),
			{ wrapper: makeWrapper() },
		);
		await waitFor(() => expect(preflightMutateAsync).toHaveBeenCalledTimes(1));
		// Re-render multiple times — preflight must not be called again.
		rerender();
		rerender();
		rerender();
		expect(preflightMutateAsync).toHaveBeenCalledTimes(1);
		// Confirm the label is stable.
		expect(result.current.sendButtonLabel).toBe("Send");
	});
});
