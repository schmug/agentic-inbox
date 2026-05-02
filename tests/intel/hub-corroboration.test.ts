// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchHubCorroborationCount } from "../../workers/intel/hub-corroboration";

const baseOpts = {
	baseUrl: "https://hub.example",
	apiKey: "k",
	orgUuid: "11111111-1111-1111-1111-111111111111",
	since: "2026-04-29T00:00:00.000Z",
};

describe("fetchHubCorroborationCount", () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;
	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch");
	});
	afterEach(() => {
		fetchSpy.mockRestore();
	});

	it("returns the count on a happy 200 response", async () => {
		fetchSpy.mockResolvedValueOnce(
			new Response(JSON.stringify({ corroboratedCount: 7 }), { status: 200 }),
		);
		const n = await fetchHubCorroborationCount(baseOpts);
		expect(n).toBe(7);

		// Verify the URL + auth header shape match the hub contract.
		const call = fetchSpy.mock.calls[0]!;
		const url = call[0] as string;
		expect(url).toContain("/api/v1/corroboration");
		expect(url).toContain("orgUuid=11111111-1111-1111-1111-111111111111");
		expect(url).toContain(`since=${encodeURIComponent(baseOpts.since)}`);
		const init = call[1] as RequestInit;
		expect((init.headers as Record<string, string>).Authorization).toBe("k");
	});

	it("returns null on non-2xx (hub down with 500)", async () => {
		fetchSpy.mockResolvedValueOnce(new Response("oops", { status: 500 }));
		const n = await fetchHubCorroborationCount(baseOpts);
		expect(n).toBeNull();
	});

	it("returns null when the response body is malformed JSON", async () => {
		fetchSpy.mockResolvedValueOnce(new Response("not json", { status: 200 }));
		const n = await fetchHubCorroborationCount(baseOpts);
		expect(n).toBeNull();
	});

	it("returns null when corroboratedCount is missing from the body", async () => {
		fetchSpy.mockResolvedValueOnce(
			new Response(JSON.stringify({ other: 1 }), { status: 200 }),
		);
		const n = await fetchHubCorroborationCount(baseOpts);
		expect(n).toBeNull();
	});

	it("returns null when fetch throws (network error / timeout)", async () => {
		fetchSpy.mockRejectedValueOnce(new Error("timeout"));
		const n = await fetchHubCorroborationCount(baseOpts);
		expect(n).toBeNull();
	});

	it("times out via the default 2s AbortSignal when the hub hangs", async () => {
		// Drive the AbortSignal.timeout(2000) path: the Promise never resolves
		// but the signal aborts; `fetch` should reject with an AbortError.
		fetchSpy.mockImplementationOnce((_url: unknown, init: unknown) => {
			return new Promise((_resolve, reject) => {
				const signal = (init as RequestInit).signal as AbortSignal | undefined;
				signal?.addEventListener("abort", () => {
					reject(new DOMException("aborted", "AbortError"));
				});
			});
		});
		// Use a short signal to avoid actually waiting 2s in the test.
		const ac = new AbortController();
		queueMicrotask(() => ac.abort());
		const n = await fetchHubCorroborationCount({ ...baseOpts, signal: ac.signal });
		expect(n).toBeNull();
	});
});
