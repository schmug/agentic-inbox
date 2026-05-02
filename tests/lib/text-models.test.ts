// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { listTextModels, type TextModelsEnv } from "../../workers/lib/text-models";
import { TEXT_MODELS } from "../../shared/mailbox-settings";

interface FakeKv {
	store: Map<string, string>;
	puts: Array<{ key: string; value: string; ttl?: number }>;
	get: KVNamespace["get"];
	put: KVNamespace["put"];
}

function fakeKv(initial: Record<string, unknown> = {}): FakeKv {
	const store = new Map(
		Object.entries(initial).map(([k, v]) => [k, JSON.stringify(v)]),
	);
	const puts: FakeKv["puts"] = [];
	const get: KVNamespace["get"] = (async (key: string, type?: unknown) => {
		const raw = store.get(key);
		if (raw === undefined) return null;
		if (type === "json" || (type && typeof type === "object" && (type as { type?: string }).type === "json")) {
			try {
				return JSON.parse(raw);
			} catch {
				return null;
			}
		}
		return raw;
	}) as KVNamespace["get"];
	const put: KVNamespace["put"] = (async (
		key: string,
		value: string,
		opts?: { expirationTtl?: number },
	) => {
		store.set(key, value);
		puts.push({ key, value, ttl: opts?.expirationTtl });
	}) as KVNamespace["put"];
	return { store, puts, get, put };
}

function asKv(fk: FakeKv): KVNamespace {
	return { get: fk.get, put: fk.put } as unknown as KVNamespace;
}

describe("listTextModels", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
	});

	it("falls back to the static list when no creds and no cache", async () => {
		const fk = fakeKv();
		const env: TextModelsEnv = { BLOOM_KV: asKv(fk) };
		const result = await listTextModels(env);
		expect(result.source).toBe("fallback");
		expect(result.models).toEqual([...TEXT_MODELS]);
	});

	it("returns the cached list without hitting the network when KV has data", async () => {
		const fetcher = vi.fn();
		const fk = fakeKv({
			"text-models:v1": {
				models: ["@cf/cached/one", "@cf/cached/two"],
				cachedAt: "2026-04-30T12:00:00Z",
			},
		});
		const env: TextModelsEnv = {
			BLOOM_KV: asKv(fk),
			CLOUDFLARE_API_TOKEN: "tok",
			CLOUDFLARE_ACCOUNT_ID: "acct",
		};
		const result = await listTextModels(env, { fetcher: fetcher as typeof fetch });
		expect(result.source).toBe("kv");
		expect(result.models).toEqual(["@cf/cached/one", "@cf/cached/two"]);
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("hits the upstream API when cache is empty and writes back to KV", async () => {
		const upstream = {
			success: true,
			result: [
				{ name: "@cf/meta/llama-3.3-70b-instruct-fp8-fast" },
				{ name: "@cf/moonshotai/kimi-k2.5" },
				// Non-`@cf/` entry should be filtered out (defensive against
				// the API drifting to include partner-routed models).
				{ name: "anthropic/claude-3" },
			],
		};
		const fetcher = vi.fn().mockResolvedValue(
			new Response(JSON.stringify(upstream), { status: 200 }),
		);
		const fk = fakeKv();
		const env: TextModelsEnv = {
			BLOOM_KV: asKv(fk),
			CLOUDFLARE_API_TOKEN: "tok",
			CLOUDFLARE_ACCOUNT_ID: "acct123",
		};
		const result = await listTextModels(env, { fetcher: fetcher as typeof fetch });

		expect(result.source).toBe("remote");
		expect(result.models).toEqual([
			"@cf/meta/llama-3.3-70b-instruct-fp8-fast",
			"@cf/moonshotai/kimi-k2.5",
		]);

		expect(fetcher).toHaveBeenCalledTimes(1);
		const url = (fetcher.mock.calls[0]![0] as string).toString();
		expect(url).toContain("/accounts/acct123/ai/models/search");
		expect(url).toContain("task=Text+Generation");
		const init = fetcher.mock.calls[0]![1] as RequestInit;
		expect(init.headers).toMatchObject({ authorization: "Bearer tok" });

		// KV write happened with the right TTL.
		// Allow a tick for the fire-and-forget put to land.
		await new Promise((r) => setTimeout(r, 0));
		expect(fk.puts).toHaveLength(1);
		expect(fk.puts[0].key).toBe("text-models:v1");
		expect(fk.puts[0].ttl).toBe(60 * 60);
	});

	it("falls back to the static list when upstream returns non-OK", async () => {
		const fetcher = vi
			.fn()
			.mockResolvedValue(new Response("nope", { status: 500 }));
		const fk = fakeKv();
		const env: TextModelsEnv = {
			BLOOM_KV: asKv(fk),
			CLOUDFLARE_API_TOKEN: "tok",
			CLOUDFLARE_ACCOUNT_ID: "acct",
		};
		const result = await listTextModels(env, { fetcher: fetcher as typeof fetch });
		expect(result.source).toBe("fallback");
		expect(result.models).toEqual([...TEXT_MODELS]);
		expect(fk.puts).toHaveLength(0); // nothing cached on a failure
	});

	it("falls back to the static list when upstream throws", async () => {
		const fetcher = vi.fn().mockRejectedValue(new Error("network"));
		const fk = fakeKv();
		const env: TextModelsEnv = {
			BLOOM_KV: asKv(fk),
			CLOUDFLARE_API_TOKEN: "tok",
			CLOUDFLARE_ACCOUNT_ID: "acct",
		};
		const result = await listTextModels(env, { fetcher: fetcher as typeof fetch });
		expect(result.source).toBe("fallback");
		expect(result.models).toEqual([...TEXT_MODELS]);
	});

	it("falls back when upstream returns zero @cf/ models", async () => {
		const fetcher = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ result: [{ name: "openai/gpt-4" }] })),
		);
		const fk = fakeKv();
		const env: TextModelsEnv = {
			BLOOM_KV: asKv(fk),
			CLOUDFLARE_API_TOKEN: "tok",
			CLOUDFLARE_ACCOUNT_ID: "acct",
		};
		const result = await listTextModels(env, { fetcher: fetcher as typeof fetch });
		expect(result.source).toBe("fallback");
		expect(result.models).toEqual([...TEXT_MODELS]);
	});
});
