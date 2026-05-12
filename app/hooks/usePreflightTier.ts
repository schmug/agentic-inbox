// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * usePreflightTier — calls POST /api/v1/mailboxes/:mailboxId/emails/preflight
 * when invoked and returns the risk tier (0 | 1 | 2).
 *
 * Rules:
 *  - Called once when the Send button is rendered (or explicitly triggered).
 *  - If preflight fails (network error, 5xx, anything), defaults to Tier 0
 *    and emits a console.warn. Never blocks sending.
 */

import { useCallback, useRef, useState } from "react";
import api from "~/services/api";

export type PreflightTier = 0 | 1 | 2;

export interface PreflightResult {
	tier: PreflightTier;
	reasons: string[];
}

export interface UsePreflightTierReturn {
	/** Current preflight tier (0 = safe default until first result). */
	tier: PreflightTier;
	reasons: string[];
	/** Whether a preflight request is in-flight. */
	isPreflight: boolean;
	/** Call to trigger a preflight check for the current email payload. */
	runPreflight: (mailboxId: string, emailPayload: unknown) => Promise<void>;
}

export function usePreflightTier(): UsePreflightTierReturn {
	const [tier, setTier] = useState<PreflightTier>(0);
	const [reasons, setReasons] = useState<string[]>([]);
	const [isPreflight, setIsPreflight] = useState(false);
	// Prevent a stale inflight response from overwriting a newer one.
	const requestIdRef = useRef(0);

	const runPreflight = useCallback(
		async (mailboxId: string, emailPayload: unknown) => {
			if (!mailboxId) return;
			setIsPreflight(true);
			const reqId = ++requestIdRef.current;
			try {
				const result = await api.preflightEmail(mailboxId, emailPayload);
				if (reqId !== requestIdRef.current) return; // stale
				setTier(result.tier);
				setReasons(result.reasons ?? []);
			} catch (err) {
				if (reqId !== requestIdRef.current) return; // stale
				console.warn(
					"[preflight] failed — defaulting to Tier 0. Sending is not blocked.",
					err,
				);
				setTier(0);
				setReasons([]);
			} finally {
				if (reqId === requestIdRef.current) {
					setIsPreflight(false);
				}
			}
		},
		[],
	);

	return { tier, reasons, isPreflight, runPreflight };
}
