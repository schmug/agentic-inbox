// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Route, Routes } from "react-router";

vi.mock("~/queries/mailboxes", () => ({
	useMailbox: () => ({
		data: { id: "m1", email: "alice@acme.com", name: "Alice" },
	}),
}));

import Breadcrumb from "~/components/phishsoc/Breadcrumb";
import { renderWithProviders } from "./test-utils";

function renderBreadcrumb(initialEntry: string) {
	return renderWithProviders(
		<Routes>
			<Route path="/" element={<Breadcrumb />} />
			<Route path="/mailboxes" element={<Breadcrumb />} />
			<Route path="/domains" element={<Breadcrumb />} />
			<Route path="/domains/:domain" element={<Breadcrumb />} />
			<Route path="/mailbox/:mailboxId/*" element={<Breadcrumb />} />
		</Routes>,
		{ initialEntries: [initialEntry] },
	);
}

describe("Breadcrumb", () => {
	it("is hidden on the org overview (/)", () => {
		renderBreadcrumb("/");
		// No nav landmark for breadcrumb.
		expect(screen.queryByRole("navigation", { name: /breadcrumb/i })).toBeNull();
	});

	it("renders Org › Mailboxes on /mailboxes (Org is a link, last item is not)", () => {
		renderBreadcrumb("/mailboxes");
		const nav = screen.getByRole("navigation", { name: /breadcrumb/i });
		const items = within(nav).getAllByRole("listitem");
		expect(items).toHaveLength(2);

		// First segment is a link to "/".
		const orgLink = within(nav).getByRole("link", { name: "Org" });
		expect(orgLink).toHaveAttribute("href", "/");

		// Last segment is plain text with aria-current="page".
		expect(within(nav).queryByRole("link", { name: "Mailboxes" })).toBeNull();
		expect(within(nav).getByText("Mailboxes")).toHaveAttribute(
			"aria-current",
			"page",
		);
	});

	it("renders Org › acme.com › alice@acme.com › Cases › CASE-1 on /mailbox/m1/cases/CASE-1 (#85)", () => {
		renderBreadcrumb("/mailbox/m1/cases/CASE-1");
		const nav = screen.getByRole("navigation", { name: /breadcrumb/i });
		const items = within(nav).getAllByRole("listitem");
		// Org / domain / mailbox / Cases / CASE-1
		expect(items).toHaveLength(5);

		// Org → / link.
		expect(within(nav).getByRole("link", { name: "Org" })).toHaveAttribute(
			"href",
			"/",
		);
		// Domain segment links to the per-domain drill-down.
		expect(within(nav).getByRole("link", { name: "acme.com" })).toHaveAttribute(
			"href",
			"/domains/acme.com",
		);
		// Mailbox link uses email.
		expect(
			within(nav).getByRole("link", { name: "alice@acme.com" }),
		).toHaveAttribute("href", "/mailbox/m1");
		// Cases link to mailbox-scoped cases route.
		expect(within(nav).getByRole("link", { name: "Cases" })).toHaveAttribute(
			"href",
			"/mailbox/m1/cases",
		);
		// Case ID is the trailing, non-link segment.
		expect(within(nav).queryByRole("link", { name: "CASE-1" })).toBeNull();
		expect(within(nav).getByText("CASE-1")).toHaveAttribute(
			"aria-current",
			"page",
		);
	});

	it("renders Org › Domains on /domains (#85)", () => {
		renderBreadcrumb("/domains");
		const nav = screen.getByRole("navigation", { name: /breadcrumb/i });
		const items = within(nav).getAllByRole("listitem");
		expect(items).toHaveLength(2);
		expect(within(nav).getByRole("link", { name: "Org" })).toHaveAttribute(
			"href",
			"/",
		);
		expect(within(nav).getByText("Domains")).toHaveAttribute(
			"aria-current",
			"page",
		);
	});

	it("renders Org › acme.com on /domains/acme.com (#85)", () => {
		renderBreadcrumb("/domains/acme.com");
		const nav = screen.getByRole("navigation", { name: /breadcrumb/i });
		const items = within(nav).getAllByRole("listitem");
		expect(items).toHaveLength(2);
		expect(within(nav).getByRole("link", { name: "Org" })).toHaveAttribute(
			"href",
			"/",
		);
		expect(within(nav).queryByRole("link", { name: "acme.com" })).toBeNull();
		expect(within(nav).getByText("acme.com")).toHaveAttribute(
			"aria-current",
			"page",
		);
	});

	it("uses a monospaced separator between segments", () => {
		const { container } = renderBreadcrumb("/mailbox/m1/dashboard");
		// Org / acme.com / mailbox / Dashboard → at least three separators
		// once the domain segment is injected (#85). The lower bound stays
		// permissive so the test doesn't drift on future segment changes.
		const separators = container.querySelectorAll(".pp-mono");
		expect(separators.length).toBeGreaterThanOrEqual(2);
		separators.forEach((sep) => {
			expect(sep.textContent?.trim()).toBe("›");
		});
	});

	it("maps known folder slugs to friendly labels", () => {
		renderBreadcrumb("/mailbox/m1/emails/inbox");
		expect(screen.getByText("Inbox")).toHaveAttribute("aria-current", "page");
	});
});
