// Copyright (c) 2026 schmug. Licensed under the Apache 2.0 license.

/**
 * Hub corroboration count fetch (#72).
 *
 * Standalone fetch helper rather than a `MispClient` method because the
 * corroboration endpoint isn't part of the MISP REST surface — it's a
 * PhishSOC-hub-only addition that sums "own attributes that got a second
 * contributor in the window."
 *
 * On any failure (non-2xx, malformed body, network error, timeout) the
 * helper returns `null`. The dashboard endpoint forwards that `null` to the
 * UI, which renders an "unavailable" placeholder instead of failing the
 * whole dashboard when the hub is unreachable.
 */

export interface FetchCorroborationOpts {
	baseUrl: string;
	apiKey: string;
	orgUuid: string;
	since: string;
	/** AbortSignal override — defaults to a 2s timeout. */
	signal?: AbortSignal;
}

export async function fetchHubCorroborationCount(
	opts: FetchCorroborationOpts,
): Promise<number | null> {
	const url = new URL(
		`${opts.baseUrl.replace(/\/$/, "")}/api/v1/corroboration`,
	);
	url.searchParams.set("orgUuid", opts.orgUuid);
	url.searchParams.set("since", opts.since);

	try {
		const res = await fetch(url.toString(), {
			headers: {
				Authorization: opts.apiKey,
				Accept: "application/json",
			},
			signal: opts.signal ?? AbortSignal.timeout(2000),
		});
		if (!res.ok) return null;
		const json = (await res.json().catch(() => null)) as
			| { corroboratedCount?: unknown }
			| null;
		const n = json?.corroboratedCount;
		if (typeof n !== "number" || !Number.isFinite(n)) return null;
		return n;
	} catch {
		// Timeout / network error / DNS — collapse to null so the caller can
		// degrade gracefully without trying to distinguish failure modes.
		return null;
	}
}
