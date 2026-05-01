// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Dynamic Workers AI text-generation model list (#64).
 *
 * Fetches `?task=Text Generation` from the Cloudflare Workers AI REST API,
 * normalizes to a `string[]` of model ids (`@cf/...`), and caches the
 * result in `BLOOM_KV` for 1 hour.
 *
 * Falls back to the curated `TEXT_MODELS` constant when:
 *  - the runtime secrets aren't configured (`CLOUDFLARE_API_TOKEN` /
 *    `CLOUDFLARE_ACCOUNT_ID` missing or empty),
 *  - the upstream call fails or returns an unexpected shape, or
 *  - KV is unavailable on the env (defensive — current deploys always
 *    bind it).
 *
 * Pure function — accepts the env-shaped object so tests can stub
 * `fetch`/KV without spinning up a full worker.
 */

import { TEXT_MODELS } from "../../shared/mailbox-settings";

export interface TextModelsEnv {
	BLOOM_KV?: KVNamespace;
	CLOUDFLARE_API_TOKEN?: string;
	CLOUDFLARE_ACCOUNT_ID?: string;
}

export interface TextModelsResult {
	models: string[];
	/** Where the response came from — used by tests and a debug header. */
	source: "kv" | "remote" | "fallback";
}

const CACHE_KEY = "text-models:v1";
const CACHE_TTL_S = 60 * 60; // 1 hour

interface CachedShape {
	models: string[];
	cachedAt: string;
}

/** Fallback list — the hand-curated set we shipped before #64. */
function fallback(): TextModelsResult {
	return { models: [...TEXT_MODELS], source: "fallback" };
}

/**
 * Read-through cache: KV → upstream API → static fallback. Always
 * resolves to a usable list even on partial failure.
 */
export async function listTextModels(
	env: TextModelsEnv,
	options: {
		fetcher?: typeof fetch;
		now?: () => number;
	} = {},
): Promise<TextModelsResult> {
	const fetcher = options.fetcher ?? globalThis.fetch;

	if (env.BLOOM_KV) {
		try {
			const cached = await env.BLOOM_KV.get(CACHE_KEY, "json");
			if (cached && isCachedShape(cached) && cached.models.length > 0) {
				return { models: cached.models, source: "kv" };
			}
		} catch (e) {
			console.error("text-models: KV read failed:", (e as Error).message);
		}
	}

	const token = env.CLOUDFLARE_API_TOKEN?.trim();
	const accountId = env.CLOUDFLARE_ACCOUNT_ID?.trim();
	if (!token || !accountId) {
		// No creds configured — fall back without bumping KV.
		return fallback();
	}

	try {
		const url = new URL(
			`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/ai/models/search`,
		);
		url.searchParams.set("task", "Text Generation");
		const resp = await fetcher(url.toString(), {
			headers: {
				authorization: `Bearer ${token}`,
				accept: "application/json",
			},
		});
		if (!resp.ok) {
			console.warn(`text-models: upstream returned ${resp.status}`);
			return fallback();
		}
		const body = (await resp.json()) as unknown;
		const models = parseModelsResponse(body);
		if (models.length === 0) {
			console.warn("text-models: upstream returned 0 models, using fallback");
			return fallback();
		}

		if (env.BLOOM_KV) {
			const payload: CachedShape = {
				models,
				cachedAt: new Date().toISOString(),
			};
			env.BLOOM_KV.put(CACHE_KEY, JSON.stringify(payload), {
				expirationTtl: CACHE_TTL_S,
			}).catch((e) => {
				// Cache write is best-effort — never block the response.
				console.error("text-models: KV write failed:", (e as Error).message);
			});
		}

		return { models, source: "remote" };
	} catch (e) {
		console.error("text-models: upstream fetch failed:", (e as Error).message);
		return fallback();
	}
}

function isCachedShape(v: unknown): v is CachedShape {
	if (!v || typeof v !== "object") return false;
	const obj = v as { models?: unknown };
	return Array.isArray(obj.models) && obj.models.every((m) => typeof m === "string");
}

/**
 * Pull `name` strings from the upstream `result[]` array. The API
 * response shape is `{ success, result: [{ name, task: { name } }] }`.
 * We only keep entries whose name starts with `@cf/` — defensive
 * against the API drifting to include partner-routed models that
 * Workers AI bindings don't accept directly.
 */
function parseModelsResponse(body: unknown): string[] {
	if (!body || typeof body !== "object") return [];
	const result = (body as { result?: unknown }).result;
	if (!Array.isArray(result)) return [];
	const names = new Set<string>();
	for (const entry of result) {
		if (!entry || typeof entry !== "object") continue;
		const name = (entry as { name?: unknown }).name;
		if (typeof name !== "string") continue;
		if (!name.startsWith("@cf/")) continue;
		names.add(name);
	}
	return [...names].sort();
}
