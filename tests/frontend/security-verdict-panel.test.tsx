// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import SecurityVerdictPanel from "~/components/email-panel/SecurityVerdictPanel";
import type { Email } from "~/types";

function makeEmail(verdictOverrides: Record<string, unknown> = {}): Email {
	const verdict = {
		action: "block",
		score: 87,
		explanation: "High-confidence phishing attempt.",
		auth: { spf: "pass", dkim: "pass", dmarc: "pass" },
		classification: { label: "phishing", confidence: 0.9, reasoning: "Suspicious link" },
		signals: ["suspicious_links"],
		...verdictOverrides,
	};
	return {
		id: "email_test",
		subject: "Urgent wire transfer",
		sender: "attacker@evil.com",
		recipient: "victim@acme.com",
		date: "2026-01-01T00:00:00Z",
		read: false,
		starred: false,
		security_verdict: JSON.stringify(verdict),
	};
}

describe("SecurityVerdictPanel — confidence chip (issue #220)", () => {
	it("shows confidence as a percentage when verdict.confidence is 0.85", () => {
		render(<SecurityVerdictPanel email={makeEmail({ confidence: 0.85 })} />);
		expect(screen.getByText(/85%/)).toBeInTheDocument();
		expect(screen.getByText(/confidence 85%/i)).toBeInTheDocument();
	});

	it("hides the confidence chip when verdict has no confidence field (pre-#105 verdict)", () => {
		render(<SecurityVerdictPanel email={makeEmail()} />);
		// No top-level confidence field → chip must not render
		expect(screen.queryByText(/· confidence/i)).not.toBeInTheDocument();
	});

	it("renders 0% for a verdict with confidence genuinely equal to zero", () => {
		render(<SecurityVerdictPanel email={makeEmail({ confidence: 0 })} />);
		expect(screen.getByText(/confidence 0%/i)).toBeInTheDocument();
	});

	it("does not render the panel at all for an allow verdict (no chip leak)", () => {
		render(<SecurityVerdictPanel email={makeEmail({ action: "allow", confidence: 0.85 })} />);
		expect(screen.queryByText(/confidence/i)).not.toBeInTheDocument();
	});
});
