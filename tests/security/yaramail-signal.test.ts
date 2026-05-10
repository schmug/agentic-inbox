// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	computeYaraScoreDelta,
	fireYaraScan,
	YARA_SCORE_CAP,
	DEFAULT_YARA_RULE_SCORES,
	type YaraMatchResult,
} from "../../workers/security/yaramail-signal";

// Mock resolveMailboxSettings so tests don't need a real R2 bucket.
// vi.mock is hoisted so this runs before any import evaluation.
vi.mock("../../workers/lib/mailbox-settings", () => ({
	resolveMailboxSettings: vi.fn(),
	stripDefaultEqual: <T>(x: T) => x,
	YaraMailScannerSettings: { parse: (x: unknown) => x },
}));

// After the mock is set up we can import the mocked function.
import { resolveMailboxSettings } from "../../workers/lib/mailbox-settings";
const mockedResolve = vi.mocked(resolveMailboxSettings);

// ── helpers ────────────────────────────────────────────────────────────────

function makeEnv() {
	return { BUCKET: {} } as unknown as { BUCKET: R2Bucket };
}

function makeCtx() {
	const scheduled: Promise<unknown>[] = [];
	return {
		ctx: { waitUntil: (p: Promise<unknown>) => { scheduled.push(p); } },
		scheduled,
	};
}

function makeRawSettings(scanner: { enabled?: boolean; endpoint_url?: string } | undefined) {
	return {
		raw: { yaramail_scanner: scanner },
		security: { enabled: false },
	} as unknown as Awaited<ReturnType<typeof resolveMailboxSettings>>;
}

// ── computeYaraScoreDelta ──────────────────────────────────────────────────

describe("computeYaraScoreDelta", () => {
	it("returns 0 for an empty match list", () => {
		expect(computeYaraScoreDelta([])).toBe(0);
	});

	it("maps known rule names via DEFAULT_YARA_RULE_SCORES", () => {
		const matches: YaraMatchResult[] = [{ rule_name: "pdf_phishing" }];
		expect(computeYaraScoreDelta(matches)).toBe(DEFAULT_YARA_RULE_SCORES.pdf_phishing);
	});

	it("uses explicit score override when provided", () => {
		const matches: YaraMatchResult[] = [{ rule_name: "pdf_phishing", score: 7 }];
		expect(computeYaraScoreDelta(matches)).toBe(7);
	});

	it("defaults unknown rule names to +5", () => {
		const matches: YaraMatchResult[] = [{ rule_name: "unknown_custom_rule" }];
		expect(computeYaraScoreDelta(matches)).toBe(5);
	});

	it("sums multiple match contributions", () => {
		const matches: YaraMatchResult[] = [
			{ rule_name: "nested_archive" },   // 10
			{ rule_name: "eml_attachment" },   // 5
		];
		expect(computeYaraScoreDelta(matches)).toBe(15);
	});

	it("caps total at YARA_SCORE_CAP regardless of match count", () => {
		const manyMatches: YaraMatchResult[] = Array.from({ length: 20 }, () => ({
			rule_name: "macro_dropper",  // 25 each
		}));
		expect(computeYaraScoreDelta(manyMatches)).toBe(YARA_SCORE_CAP);
		expect(YARA_SCORE_CAP).toBe(30);
	});

	it("caps even when explicit scores sum beyond the cap", () => {
		const matches: YaraMatchResult[] = [
			{ rule_name: "x", score: 20 },
			{ rule_name: "y", score: 20 },
		];
		expect(computeYaraScoreDelta(matches)).toBe(YARA_SCORE_CAP);
	});
});

// ── fireYaraScan ───────────────────────────────────────────────────────────

describe("fireYaraScan — sidecar disabled", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.clearAllMocks();
	});

	it("does not fire a request when yaramail_scanner is absent", async () => {
		mockedResolve.mockResolvedValue(makeRawSettings(undefined));
		const { ctx } = makeCtx();
		await fireYaraScan(makeEnv(), ctx, "user@example.com", "msg-1", "attachments/msg-1/att-1/file.pdf");
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("does not fire a request when enabled is false", async () => {
		mockedResolve.mockResolvedValue(makeRawSettings({ enabled: false, endpoint_url: "https://sidecar.example.com/scan" }));
		const { ctx } = makeCtx();
		await fireYaraScan(makeEnv(), ctx, "user@example.com", "msg-1", "attachments/msg-1/att-1/file.pdf");
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it("does not fire a request when endpoint_url is missing", async () => {
		mockedResolve.mockResolvedValue(makeRawSettings({ enabled: true }));
		const { ctx } = makeCtx();
		await fireYaraScan(makeEnv(), ctx, "user@example.com", "msg-1", "attachments/msg-1/att-1/file.pdf");
		expect(fetchSpy).not.toHaveBeenCalled();
	});
});

describe("fireYaraScan — sidecar enabled", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok"));
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.clearAllMocks();
	});

	it("fires a POST to the configured endpoint with the correct payload", async () => {
		const endpointUrl = "https://sidecar.example.com/scan";
		mockedResolve.mockResolvedValue(
			makeRawSettings({ enabled: true, endpoint_url: endpointUrl }),
		);
		const { ctx, scheduled } = makeCtx();

		await fireYaraScan(
			makeEnv(),
			ctx,
			"user@example.com",
			"msg-abc",
			"attachments/msg-abc/att-1/report.pdf",
			"https://presigned.example.com/token",
		);

		// The request must be scheduled (fire-and-forget via waitUntil)
		expect(scheduled).toHaveLength(1);

		// Drain the scheduled promise so fetch is actually called
		await scheduled[0];

		expect(fetchSpy).toHaveBeenCalledOnce();
		const [calledUrl, calledInit] = fetchSpy.mock.calls[0] as [string, RequestInit];

		// CodeQL URL parse rule: compare hostname, not substring
		expect(new URL(calledUrl).hostname).toBe("sidecar.example.com");

		const body = JSON.parse(calledInit.body as string);
		expect(body).toMatchObject({
			emailId: "msg-abc",
			r2Key: "attachments/msg-abc/att-1/report.pdf",
			mailboxId: "user@example.com",
			presignedUrl: "https://presigned.example.com/token",
		});
	});

	it("uses an empty string for presignedUrl when not provided", async () => {
		mockedResolve.mockResolvedValue(
			makeRawSettings({ enabled: true, endpoint_url: "https://sidecar.example.com/scan" }),
		);
		const { ctx, scheduled } = makeCtx();

		await fireYaraScan(makeEnv(), ctx, "user@example.com", "msg-1", "attachments/msg-1/att-1/file.pdf");
		await scheduled[0];

		const body = JSON.parse((fetchSpy.mock.calls[0] as [string, RequestInit])[1].body as string);
		expect(body.presignedUrl).toBe("");
	});

	it("swallows sidecar timeout — verdict is unchanged, no error propagates", async () => {
		mockedResolve.mockResolvedValue(
			makeRawSettings({ enabled: true, endpoint_url: "https://sidecar.example.com/scan" }),
		);
		// Simulate a network timeout (AbortError)
		fetchSpy.mockRejectedValue(Object.assign(new Error("The operation was aborted"), { name: "AbortError" }));

		const { ctx, scheduled } = makeCtx();
		// fireYaraScan itself must not throw
		await expect(
			fireYaraScan(makeEnv(), ctx, "user@example.com", "msg-1", "attachments/msg-1/att-1/file.pdf"),
		).resolves.toBeUndefined();

		// Draining the scheduled promise must also not throw
		await expect(scheduled[0]).resolves.toBeUndefined();
	});

	it("swallows other network errors — no propagation", async () => {
		mockedResolve.mockResolvedValue(
			makeRawSettings({ enabled: true, endpoint_url: "https://sidecar.example.com/scan" }),
		);
		fetchSpy.mockRejectedValue(new Error("Network unreachable"));

		const { ctx, scheduled } = makeCtx();
		await fireYaraScan(makeEnv(), ctx, "user@example.com", "msg-1", "attachments/msg-1/att-1/file.pdf");
		await expect(scheduled[0]).resolves.toBeUndefined();
	});
});
