// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Tests for the composer send-risk UI (issue #263).
 *
 * Acceptance:
 * - Send button shows "Send" when preflight returns Tier 0
 * - Send button shows "Send (re-auth)" when preflight returns Tier 1
 * - Send button shows "Send (verify)" when preflight returns Tier 2
 * - Preflight network failure → button shows "Send" (Tier 0 default), send proceeds
 * - data-testid attributes are present on all send button variants
 *
 * These tests exercise ComposeSendButton directly (unit) and the
 * usePreflightTier hook via a thin wrapper (integration).
 *
 * URL mock rule (CLAUDE.md): all fetch dispatching uses new URL(url).hostname
 * — never url.startsWith/url.includes.
 */

import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import ComposeSendButton from "~/components/ComposeSendButton";
import { usePreflightTier } from "~/hooks/usePreflightTier";
import { renderHook } from "@testing-library/react";

// ---------------------------------------------------------------------------
// ComposeSendButton unit tests
// ---------------------------------------------------------------------------

describe("ComposeSendButton — Tier 0", () => {
	it("renders with text 'Send' and data-testid='send-button-tier-0'", () => {
		render(
			<ComposeSendButton
				tier={0}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);

		const btn = screen.getByTestId("send-button-tier-0");
		expect(btn).toBeInTheDocument();
		expect(btn).toHaveTextContent("Send");
		// Tier-0 must NOT show the step-up labels
		expect(screen.queryByText(/re-auth/i)).not.toBeInTheDocument();
		expect(screen.queryByText(/verify/i)).not.toBeInTheDocument();
	});

	it("is type=submit so the form's onSubmit fires normally", () => {
		render(
			<ComposeSendButton
				tier={0}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient=""
			/>,
		);
		const btn = screen.getByTestId("send-button-tier-0");
		expect(btn).toHaveAttribute("type", "submit");
	});
});

describe("ComposeSendButton — Tier 1", () => {
	it("renders with text 'Send (re-auth)' and data-testid='send-button-tier-1'", () => {
		render(
			<ComposeSendButton
				tier={1}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);

		const btn = screen.getByTestId("send-button-tier-1");
		expect(btn).toBeInTheDocument();
		expect(btn).toHaveTextContent("Send (re-auth)");
	});

	it("does NOT render the Tier-2 recipient-confirmation input", () => {
		render(
			<ComposeSendButton
				tier={1}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);
		expect(screen.queryByTestId("tier-2-confirm-input")).not.toBeInTheDocument();
	});

	it("clicking the button shows placeholder alert for step-up auth", async () => {
		const user = userEvent.setup();
		const alertSpy = vi.spyOn(window, "alert").mockImplementation(() => {});

		render(
			<ComposeSendButton
				tier={1}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);

		await user.click(screen.getByTestId("send-button-tier-1"));
		expect(alertSpy).toHaveBeenCalledWith("Step-up auth not yet configured");
		alertSpy.mockRestore();
	});
});

describe("ComposeSendButton — Tier 2", () => {
	it("renders with text 'Send (verify)' and data-testid='send-button-tier-2'", () => {
		render(
			<ComposeSendButton
				tier={2}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);

		const btn = screen.getByTestId("send-button-tier-2");
		expect(btn).toBeInTheDocument();
		expect(btn).toHaveTextContent("Send (verify)");
	});

	it("renders the recipient-confirmation input for Tier 2", () => {
		render(
			<ComposeSendButton
				tier={2}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);
		expect(screen.getByTestId("tier-2-confirm-input")).toBeInTheDocument();
	});

	it("button is disabled until the user types the matching recipient address", async () => {
		const user = userEvent.setup();

		render(
			<ComposeSendButton
				tier={2}
				isSending={false}
				isSavingDraft={false}
				primaryRecipient="alice@example.com"
			/>,
		);

		const btn = screen.getByTestId("send-button-tier-2");
		const input = screen.getByTestId("tier-2-confirm-input");

		// Button starts disabled (phrase is empty / no match)
		expect(btn).toBeDisabled();

		// Partial match still disabled
		await user.type(input, "alice");
		expect(btn).toBeDisabled();

		// Full match (case-insensitive) enables the button
		await user.clear(input);
		await user.type(input, "ALICE@EXAMPLE.COM");
		expect(btn).not.toBeDisabled();
	});
});

// ---------------------------------------------------------------------------
// usePreflightTier hook integration tests
// ---------------------------------------------------------------------------

describe("usePreflightTier — fetch mock integration", () => {
	const MAILBOX_ID = "mbx_test";
	const PREFLIGHT_HOSTNAME = "localhost";

	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	function makeFetchMock(
		response: { tier: 0 | 1 | 2; reasons: string[] } | "error",
	) {
		return vi.fn(async (url: string | URL | Request) => {
			const urlStr = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
			// CRITICAL: parse hostname — never use startsWith/includes (CLAUDE.md)
			const parsed = new URL(urlStr, "http://localhost");
			if (
				parsed.hostname === PREFLIGHT_HOSTNAME &&
				parsed.pathname.includes("/preflight")
			) {
				if (response === "error") {
					throw new TypeError("Network error (simulated)");
				}
				return new Response(JSON.stringify(response), {
					status: 200,
					headers: { "Content-Type": "application/json" },
				});
			}
			return new Response(JSON.stringify({}), { status: 404 });
		});
	}

	it("returns Tier 0 by default before any preflight call", () => {
		const { result } = renderHook(() => usePreflightTier());
		expect(result.current.tier).toBe(0);
		expect(result.current.isPreflight).toBe(false);
	});

	it("updates tier to 0 when preflight returns Tier 0", async () => {
		globalThis.fetch = makeFetchMock({ tier: 0, reasons: [] });
		const { result } = renderHook(() => usePreflightTier());

		await act(async () => {
			await result.current.runPreflight(MAILBOX_ID, { to: "alice@example.com" });
		});

		expect(result.current.tier).toBe(0);
		expect(result.current.isPreflight).toBe(false);
	});

	it("updates tier to 1 when preflight returns Tier 1", async () => {
		globalThis.fetch = makeFetchMock({ tier: 1, reasons: ["suspicious domain"] });
		const { result } = renderHook(() => usePreflightTier());

		await act(async () => {
			await result.current.runPreflight(MAILBOX_ID, { to: "alice@example.com" });
		});

		expect(result.current.tier).toBe(1);
		expect(result.current.reasons).toEqual(["suspicious domain"]);
	});

	it("updates tier to 2 when preflight returns Tier 2", async () => {
		globalThis.fetch = makeFetchMock({ tier: 2, reasons: ["known phishing domain"] });
		const { result } = renderHook(() => usePreflightTier());

		await act(async () => {
			await result.current.runPreflight(MAILBOX_ID, { to: "alice@example.com" });
		});

		expect(result.current.tier).toBe(2);
	});

	it("defaults to Tier 0 and does NOT throw when preflight network request fails", async () => {
		globalThis.fetch = makeFetchMock("error");
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { result } = renderHook(() => usePreflightTier());

		// Should not throw even though fetch rejects
		await act(async () => {
			await result.current.runPreflight(MAILBOX_ID, { to: "alice@example.com" });
		});

		expect(result.current.tier).toBe(0);
		expect(result.current.isPreflight).toBe(false);
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("[preflight] failed"),
			expect.any(Error),
		);
		warnSpy.mockRestore();
	});

	it("defaults to Tier 0 and warns when preflight returns 5xx", async () => {
		globalThis.fetch = vi.fn(async () =>
			new Response(JSON.stringify({ error: "Internal Server Error" }), {
				status: 500,
				headers: { "Content-Type": "application/json" },
			}),
		);
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const { result } = renderHook(() => usePreflightTier());

		await act(async () => {
			await result.current.runPreflight(MAILBOX_ID, { to: "alice@example.com" });
		});

		expect(result.current.tier).toBe(0);
		expect(warnSpy).toHaveBeenCalledWith(
			expect.stringContaining("[preflight] failed"),
			expect.anything(),
		);
		warnSpy.mockRestore();
	});
});
