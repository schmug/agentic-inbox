// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { describe, expect, it } from "vitest";
import { classifySend, type ClassifySendInput } from "../../workers/security/send-risk";

// ── helpers ──────────────────────────────────────────────────────────────────

function make(overrides: Partial<ClassifySendInput> = {}): ClassifySendInput {
	return {
		to: "alice@external.com",
		mailboxId: "operator@internal.example",
		...overrides,
	};
}

// ── Tier 0 ───────────────────────────────────────────────────────────────────

describe("classifySend — Tier 0 (no restriction)", () => {
	it("internal-only send returns Tier 0", () => {
		const result = classifySend(make({ to: "colleague@internal.example" }));
		expect(result.tier).toBe(0);
		expect(result.reasons).toHaveLength(0);
	});

	it("internal CC and BCC do not trigger Tier 1", () => {
		const result = classifySend(
			make({
				to: "a@internal.example",
				cc: "b@internal.example",
				bcc: "c@internal.example",
			}),
		);
		expect(result.tier).toBe(0);
	});

	it("reply with no suspicious content stays Tier 0 (internal)", () => {
		const result = classifySend(
			make({
				to: "boss@internal.example",
				subject: "Re: Team lunch",
				body: "Sounds great, see you then!",
			}),
		);
		expect(result.tier).toBe(0);
	});
});

// ── Tier 1 ───────────────────────────────────────────────────────────────────

describe("classifySend — Tier 1 (Access re-prompt)", () => {
	it("external recipient triggers Tier 1", () => {
		const result = classifySend(make({ to: "vendor@external.com" }));
		expect(result.tier).toBe(1);
		expect(result.reasons.some((r) => r.includes("External recipient"))).toBe(true);
	});

	it("external recipient in CC triggers Tier 1", () => {
		const result = classifySend(
			make({ to: "colleague@internal.example", cc: "external@other.org" }),
		);
		expect(result.tier).toBe(1);
		expect(result.reasons.some((r) => r.includes("External"))).toBe(true);
	});

	it("more than 10 recipients triggers Tier 1 even if all internal", () => {
		const many = Array.from({ length: 11 }, (_, i) => `user${i}@internal.example`);
		const result = classifySend(make({ to: many }));
		expect(result.tier).toBe(1);
		expect(result.reasons.some((r) => r.includes("High recipient count"))).toBe(true);
	});

	it("exactly 10 recipients does NOT trigger count check", () => {
		const ten = Array.from({ length: 10 }, (_, i) => `user${i}@internal.example`);
		const result = classifySend(make({ to: ten }));
		// Still Tier 0 if all internal (count ≤ 10)
		expect(result.tier).toBe(0);
	});
});

// ── Tier 2 ───────────────────────────────────────────────────────────────────

describe("classifySend — Tier 2 (step-up required)", () => {
	it.each([
		["wire transfer", "Please send a wire transfer of $10,000"],
		["wire funds", "I need you to wire funds immediately"],
		["bank details", "Here are my bank details for the transfer"],
		["gift card", "Buy $500 in gift card codes and share them"],
		["mfa code", "Enter the MFA code 123456 now"],
		["one-time code", "Share your one-time code with me"],
		["reset my password", "Help me reset my password via this link"],
		["urgent payment", "This is an urgent payment request"],
	])("keyword '%s' in body triggers Tier 2", (_kw, body) => {
		const result = classifySend(make({ to: "colleague@internal.example", body }));
		expect(result.tier).toBe(2);
		expect(result.reasons.some((r) => r.includes("keyword"))).toBe(true);
	});

	it("keyword in subject triggers Tier 2", () => {
		const result = classifySend(
			make({
				to: "colleague@internal.example",
				subject: "Wire transfer request",
				body: "Please process.",
			}),
		);
		expect(result.tier).toBe(2);
	});

	it("keyword matching is case-insensitive", () => {
		const result = classifySend(
			make({ to: "colleague@internal.example", body: "WIRE TRANSFER details below" }),
		);
		expect(result.tier).toBe(2);
	});

	it.each([
		"invoice.pdf.exe",
		"report.docx.bat",
		"document.pdf.vbs",
		"file.txt.cmd",
		"setup.zip.scr",
	])("double-extension attachment '%s' triggers Tier 2", (filename) => {
		const result = classifySend(
			make({ to: "colleague@internal.example", attachments: [{ filename }] }),
		);
		expect(result.tier).toBe(2);
		expect(result.reasons.some((r) => r.includes("Suspicious attachment"))).toBe(true);
	});

	it("single-extension attachment does NOT trigger Tier 2", () => {
		const result = classifySend(
			make({ to: "colleague@internal.example", attachments: [{ filename: "report.pdf" }] }),
		);
		expect(result.tier).toBe(0);
	});
});

// ── Tier 2 overrides Tier 1 ──────────────────────────────────────────────────

describe("classifySend — tier precedence", () => {
	it("Tier-2 keyword on an external send returns Tier 2, not Tier 1", () => {
		const result = classifySend(
			make({
				to: "vendor@external.com",
				body: "Send me gift card codes",
			}),
		);
		expect(result.tier).toBe(2);
		// Both reasons present
		expect(result.reasons.some((r) => r.includes("keyword"))).toBe(true);
		expect(result.reasons.some((r) => r.includes("External"))).toBe(true);
	});

	it("multiple Tier-2 signals all appear in reasons", () => {
		const result = classifySend(
			make({
				to: "colleague@internal.example",
				body: "wire transfer now",
				attachments: [{ filename: "proof.pdf.exe" }],
			}),
		);
		expect(result.tier).toBe(2);
		expect(result.reasons.length).toBeGreaterThanOrEqual(2);
	});
});

// ── edge cases ───────────────────────────────────────────────────────────────

describe("classifySend — edge cases", () => {
	it("empty to array with no mailboxId domain is Tier 0", () => {
		const result = classifySend({ to: [], mailboxId: "noemail" });
		expect(result.tier).toBe(0);
	});

	it("null body and subject do not throw", () => {
		expect(() =>
			classifySend(make({ subject: null, body: null })),
		).not.toThrow();
	});

	it("attachment with no filename does not throw", () => {
		expect(() =>
			classifySend(make({ attachments: [{ filename: null }] })),
		).not.toThrow();
	});

	it("comma-separated string in 'to' is parsed correctly", () => {
		const result = classifySend(
			make({
				to: "a@internal.example, b@external.org",
				mailboxId: "me@internal.example",
			}),
		);
		expect(result.tier).toBe(1); // b@external.org is external
	});
});

// ── Agent-authored tier bump (issue #266) ────────────────────────────────────

describe("classifySend — createdBy: 'agent' bumps tier (issue #266)", () => {
	it("agent-authored external send (Tier 1 base) becomes Tier 2", () => {
		const result = classifySend(
			make({ to: "vendor@external.com", createdBy: "agent" }),
		);
		expect(result.tier).toBe(2);
		expect(result.reasons.some((r) => r.includes("Agent-authored"))).toBe(true);
		// Original Tier-1 reason still surfaces.
		expect(result.reasons.some((r) => r.includes("External"))).toBe(true);
	});

	it("agent-authored internal-only send stays Tier 0", () => {
		const result = classifySend(
			make({ to: "colleague@internal.example", createdBy: "agent" }),
		);
		expect(result.tier).toBe(0);
		expect(result.reasons).toHaveLength(0);
	});

	it("user-authored external send remains Tier 1 (unchanged)", () => {
		const result = classifySend(
			make({ to: "vendor@external.com", createdBy: "user" }),
		);
		expect(result.tier).toBe(1);
		expect(result.reasons.some((r) => r.includes("Agent-authored"))).toBe(false);
	});

	it("omitting createdBy preserves base tier (default behavior)", () => {
		const result = classifySend(make({ to: "vendor@external.com" }));
		expect(result.tier).toBe(1);
		expect(result.reasons.some((r) => r.includes("Agent-authored"))).toBe(false);
	});

	it("agent-authored Tier-2 send stays Tier 2 (no double bump) and surfaces provenance", () => {
		const result = classifySend(
			make({
				to: "vendor@external.com",
				body: "wire transfer please",
				createdBy: "agent",
			}),
		);
		expect(result.tier).toBe(2);
		// Reason emitted so audit reviewers see provenance on every non-zero
		// agent send, not just the ones that got bumped from Tier 1.
		expect(result.reasons.some((r) => r.includes("Agent-authored"))).toBe(true);
	});

	it("agent-authored high-recipient-count send (Tier 1 base) becomes Tier 2", () => {
		const many = Array.from({ length: 11 }, (_, i) => `user${i}@internal.example`);
		const result = classifySend(make({ to: many, createdBy: "agent" }));
		expect(result.tier).toBe(2);
		expect(result.reasons.some((r) => r.includes("High recipient count"))).toBe(true);
		expect(result.reasons.some((r) => r.includes("Agent-authored"))).toBe(true);
	});
});
