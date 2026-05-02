// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import api from "~/services/api";
import HubInviteModal from "~/components/HubInviteModal";
import { renderWithProviders } from "./test-utils";

// Mock the api client — we want the mutation hook (real react-query) to call
// our stub, not the worker. Spying on the imported module's method is enough
// because `api` is a const object exported as default.
vi.mock("~/services/api", async () => {
	const actual = await vi.importActual<typeof import("~/services/api")>(
		"~/services/api",
	);
	return {
		...actual,
		default: {
			...actual.default,
			createHubInvite: vi.fn(),
		},
	};
});

const createHubInvite = api.createHubInvite as unknown as ReturnType<
	typeof vi.fn
>;

describe("HubInviteModal", () => {
	const onOpenChange = vi.fn();

	beforeEach(() => {
		createHubInvite.mockReset();
		onOpenChange.mockReset();
		// Default clipboard mock — individual tests override.
		Object.defineProperty(globalThis, "navigator", {
			value: {
				...globalThis.navigator,
				clipboard: { writeText: vi.fn().mockResolvedValue(undefined) },
			},
			configurable: true,
		});
	});

	afterEach(() => {
		vi.clearAllMocks();
	});

	function render(open = true) {
		return renderWithProviders(
			<HubInviteModal
				open={open}
				mailboxId="m1"
				sharingGroup={{ uuid: "sg-1", name: "Trusted retailers" }}
				onOpenChange={onOpenChange}
			/>,
		);
	}

	it("submits the form, shows the token, and writes it to the clipboard on Copy", async () => {
		createHubInvite.mockResolvedValue({
			token: "tok-abcdef-123456",
			expires_at: "2026-05-04T12:00:00.000Z",
		});

		render();

		// Form is visible first.
		expect(screen.getByRole("button", { name: /issue invite/i })).toBeInTheDocument();
		expect(screen.queryByLabelText(/invite token/i)).not.toBeInTheDocument();

		const noteInput = screen.getByLabelText(/note/i);
		await userEvent.type(noteInput, "for alice@example.com");

		await userEvent.click(screen.getByRole("button", { name: /issue invite/i }));

		// Token shows up in a read-only field.
		const tokenInput = await screen.findByLabelText(/invite token/i);
		expect(tokenInput).toHaveValue("tok-abcdef-123456");
		expect(tokenInput).toHaveAttribute("readonly");
		expect(screen.getByText(/won't be shown again/i)).toBeInTheDocument();
		// Expiry timestamp rendered.
		expect(screen.getByText(/expires/i)).toBeInTheDocument();

		// Worker proxy was called with the right body.
		expect(createHubInvite).toHaveBeenCalledWith("m1", {
			sharing_group_uuid: "sg-1",
			note: "for alice@example.com",
			ttl_hours: 72,
		});

		// Copy button writes the token to the clipboard.
		await userEvent.click(screen.getByRole("button", { name: /^copy$/i }));
		const writeText = (navigator.clipboard as unknown as {
			writeText: ReturnType<typeof vi.fn>;
		}).writeText;
		expect(writeText).toHaveBeenCalledWith("tok-abcdef-123456");
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /copied/i })).toBeInTheDocument(),
		);
	});

	it("clears the token from the DOM when the modal closes", async () => {
		createHubInvite.mockResolvedValue({
			token: "tok-secret-xyz",
			expires_at: "2026-05-04T12:00:00.000Z",
		});

		const { rerender } = render(true);
		await userEvent.click(screen.getByRole("button", { name: /issue invite/i }));
		const tokenInput = await screen.findByLabelText(/invite token/i);
		expect(tokenInput).toHaveValue("tok-secret-xyz");

		// Close via the Done button — handler flips parent open=false. Then
		// rerender with open=false to simulate the parent's response. The
		// token field, the warning, and the token value must all be gone.
		await userEvent.click(screen.getByRole("button", { name: /done/i }));
		expect(onOpenChange).toHaveBeenCalledWith(false);

		rerender(
			<HubInviteModal
				open={false}
				mailboxId="m1"
				sharingGroup={{ uuid: "sg-1", name: "Trusted retailers" }}
				onOpenChange={onOpenChange}
			/>,
		);

		await waitFor(() => {
			expect(screen.queryByLabelText(/invite token/i)).not.toBeInTheDocument();
		});
		expect(screen.queryByText("tok-secret-xyz")).not.toBeInTheDocument();
		expect(screen.queryByText(/won't be shown again/i)).not.toBeInTheDocument();
		// The token value must not appear ANYWHERE in the document tree.
		expect(document.body.innerHTML).not.toContain("tok-secret-xyz");
	});

	it("falls back to a focused, selected input when clipboard.writeText is unavailable", async () => {
		createHubInvite.mockResolvedValue({
			token: "tok-fallback-123",
			expires_at: "2026-05-04T12:00:00.000Z",
		});
		// Clipboard absent.
		Object.defineProperty(globalThis, "navigator", {
			value: { ...globalThis.navigator, clipboard: undefined },
			configurable: true,
		});

		render();
		await userEvent.click(screen.getByRole("button", { name: /issue invite/i }));
		const tokenInput = (await screen.findByLabelText(/invite token/i)) as HTMLInputElement;

		await userEvent.click(screen.getByRole("button", { name: /^copy$/i }));

		// Fallback hint surfaces and the input is focused.
		expect(await screen.findByText(/clipboard access denied/i)).toBeInTheDocument();
		expect(document.activeElement).toBe(tokenInput);
	});
});
