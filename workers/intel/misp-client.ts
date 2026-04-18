// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * MISP-compatible client. Posts events to our hub (or any MISP instance that
 * accepts the standard REST shape) and pulls the hub's published feeds.
 *
 * Auth matches MISP convention: `Authorization: <api-key>` (not Bearer).
 */

import type { MispEvent } from "./report";

export interface MispClientConfig {
	baseUrl: string;
	apiKey: string;
}

export class MispClient {
	constructor(private cfg: MispClientConfig) {}

	async postEvent(event: MispEvent): Promise<{ uuid: string } | null> {
		const res = await fetch(`${this.cfg.baseUrl.replace(/\/$/, "")}/events`, {
			method: "POST",
			headers: {
				"Authorization": this.cfg.apiKey,
				"Accept": "application/json",
				"Content-Type": "application/json",
			},
			body: JSON.stringify(event),
			signal: AbortSignal.timeout(10000),
		});
		if (!res.ok) {
			const body = await res.text().catch(() => "");
			console.error(`hub POST /events ${res.status}: ${body.slice(0, 200)}`);
			return null;
		}
		const json = (await res.json().catch(() => null)) as { Event?: { uuid?: string } } | null;
		return json?.Event?.uuid ? { uuid: json.Event.uuid } : null;
	}

	async fetchDestroyList(): Promise<string[]> {
		const res = await fetch(`${this.cfg.baseUrl.replace(/\/$/, "")}/feeds/destroylist.txt`, {
			headers: { "Authorization": this.cfg.apiKey, "Accept": "text/plain" },
			signal: AbortSignal.timeout(10000),
		});
		if (!res.ok) return [];
		const body = await res.text();
		return body.split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
	}
}
