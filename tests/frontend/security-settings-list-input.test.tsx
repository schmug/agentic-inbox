// Regression for the comma-separated list inputs in SecuritySettingsPanel
// (allowlist senders/domains, trusted authserv-ids).
//
// The previous controlled-input pattern re-emitted `parsed.join(", ")` as the
// input value, which collapsed partial entries before the user reached the
// next comma — typing `dmg, rtf, ace` ended up as a single `["dmgrtface"]`
// instead of three entries. The fix holds the raw draft string locally and
// only resyncs the displayed text when the parent's value diverges from what
// the input last emitted.
//
// These tests TYPE the list one character at a time (userEvent.type) — pasting
// would mask the bug because the parser sees the full string in one go.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { SecuritySettingsPanel } from "~/components/SecuritySettingsPanel";
import type { SecuritySettings } from "~/types";
import { renderWithProviders } from "./test-utils";

function ControlledHost({
	initial,
	onLatest,
}: {
	initial?: SecuritySettings;
	onLatest: (next: SecuritySettings) => void;
}) {
	const [security, setSecurity] = useState<SecuritySettings>(
		initial ?? { enabled: true },
	);
	return (
		<SecuritySettingsPanel
			value={security}
			onChange={(next) => {
				setSecurity(next);
				onLatest(next);
			}}
		/>
	);
}

describe("SecuritySettingsPanel · comma-separated list inputs", () => {
	it("captures three entries when the user types a senders list one char at a time", async () => {
		const user = userEvent.setup();
		const onLatest = vi.fn();
		renderWithProviders(<ControlledHost onLatest={onLatest} />);

		const input = screen.getByLabelText(/allowed senders/i);
		await user.type(input, "ceo@a.com, cfo@b.com, ops@c.com");

		expect(input).toHaveValue("ceo@a.com, cfo@b.com, ops@c.com");
		const last = onLatest.mock.calls.at(-1)?.[0] as SecuritySettings;
		expect(last.allowlist_senders).toEqual([
			"ceo@a.com",
			"cfo@b.com",
			"ops@c.com",
		]);
	});

	it("captures three entries when the user types a domains list one char at a time", async () => {
		const user = userEvent.setup();
		const onLatest = vi.fn();
		renderWithProviders(<ControlledHost onLatest={onLatest} />);

		const input = screen.getByLabelText(/allowed domains/i);
		await user.type(input, "company.com, vendor.com, partner.com");

		expect(input).toHaveValue("company.com, vendor.com, partner.com");
		const last = onLatest.mock.calls.at(-1)?.[0] as SecuritySettings;
		expect(last.allowlist_domains).toEqual([
			"company.com",
			"vendor.com",
			"partner.com",
		]);
	});

	it("captures three entries in the trusted authserv-ids input (no label)", async () => {
		const user = userEvent.setup();
		const onLatest = vi.fn();
		renderWithProviders(<ControlledHost onLatest={onLatest} />);

		const input = screen.getByPlaceholderText(/mx\.cloudflare\.net/i);
		await user.type(input, "mx.cloudflare.net, mx.google.com, mx.proton.me");

		const last = onLatest.mock.calls.at(-1)?.[0] as SecuritySettings;
		expect(last.trusted_authserv_ids).toEqual([
			"mx.cloudflare.net",
			"mx.google.com",
			"mx.proton.me",
		]);
	});

	it("resyncs the displayed text when the parent's value changes externally", async () => {
		const onLatest = vi.fn();
		const { rerender } = renderWithProviders(
			<SecuritySettingsPanel
				value={{ enabled: true, allowlist_senders: ["alice@example.com"] }}
				onChange={onLatest}
			/>,
		);

		const input = screen.getByLabelText(/allowed senders/i);
		expect(input).toHaveValue("alice@example.com");

		rerender(
			<SecuritySettingsPanel
				value={{ enabled: true, allowlist_senders: ["bob@example.com", "carol@example.com"] }}
				onChange={onLatest}
			/>,
		);

		expect(input).toHaveValue("bob@example.com, carol@example.com");
	});
});
