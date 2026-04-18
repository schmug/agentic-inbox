// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Build a MISP-compatible event from a locally-classified phish.
 *
 * Anonymization policy (applied here, asserted by tests in `report.test.ts`
 * once we add them): strip the `to`/`cc`/`bcc` recipients, keep the `from`
 * address and domain, keep the subject, replace the body with a sha256 hash,
 * keep all extracted URLs verbatim (those ARE the shareable intel).
 *
 * The client in `misp-client.ts` handles transport + auth.
 */

export interface LocalPhishReportInput {
	/** Reporting org UUID assigned by the hub. */
	orgUuid?: string;
	/** Desired MISP sharing group for this event. */
	sharingGroupUuid?: string;
	/** Short human-readable title ("Invoice phish impersonating Acme"). */
	info: string;
	/** Reporter's observation time (ISO 8601). */
	observedAt: string;
	sender: string;
	subject: string;
	/** Parsed body as plain text. */
	bodyText: string;
	urls: Array<{ url: string; hostname: string }>;
	/** Optional attachment SHA-256 hashes. */
	attachmentSha256?: string[];
}

export interface MispEvent {
	Event: {
		uuid: string;
		info: string;
		date: string; // YYYY-MM-DD
		timestamp: string; // unix seconds as string, per MISP convention
		analysis: "0" | "1" | "2";
		threat_level_id: "1" | "2" | "3" | "4";
		distribution: "0" | "1" | "2" | "3" | "4";
		orgc_uuid?: string;
		sharing_group_uuid?: string;
		Tag: Array<{ name: string }>;
		Attribute: Array<{
			uuid: string;
			type: string;
			category: string;
			value: string;
			to_ids: boolean;
			comment?: string;
		}>;
	};
}

async function sha256(s: string): Promise<string> {
	const data = new TextEncoder().encode(s);
	const hash = await crypto.subtle.digest("SHA-256", data);
	return Array.from(new Uint8Array(hash))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function buildMispEvent(input: LocalPhishReportInput): Promise<MispEvent> {
	const now = new Date();
	const date = now.toISOString().slice(0, 10);
	const timestamp = Math.floor(now.getTime() / 1000).toString();

	const bodyHash = await sha256(input.bodyText);
	const senderDomain = input.sender.split("@")[1] ?? "";

	const attrs: MispEvent["Event"]["Attribute"] = [];

	attrs.push({
		uuid: crypto.randomUUID(),
		type: "email-src",
		category: "Payload delivery",
		value: input.sender,
		to_ids: true,
		comment: "Reported sender",
	});
	if (senderDomain) {
		attrs.push({
			uuid: crypto.randomUUID(),
			type: "email-src-display-name",
			category: "Payload delivery",
			value: senderDomain,
			to_ids: false,
		});
	}
	attrs.push({
		uuid: crypto.randomUUID(),
		type: "email-subject",
		category: "Payload delivery",
		value: input.subject.slice(0, 500),
		to_ids: false,
	});
	attrs.push({
		uuid: crypto.randomUUID(),
		type: "sha256",
		category: "Payload delivery",
		value: bodyHash,
		to_ids: false,
		comment: "sha256 of plain-text body",
	});
	for (const u of input.urls) {
		attrs.push({
			uuid: crypto.randomUUID(),
			type: "url",
			category: "Network activity",
			value: u.url,
			to_ids: true,
		});
		attrs.push({
			uuid: crypto.randomUUID(),
			type: "domain",
			category: "Network activity",
			value: u.hostname,
			to_ids: true,
		});
	}
	for (const h of input.attachmentSha256 ?? []) {
		attrs.push({
			uuid: crypto.randomUUID(),
			type: "sha256",
			category: "Payload delivery",
			value: h,
			to_ids: true,
			comment: "Attachment SHA-256",
		});
	}

	return {
		Event: {
			uuid: crypto.randomUUID(),
			info: input.info.slice(0, 256),
			date,
			timestamp,
			analysis: "1",
			threat_level_id: "2",
			// Distribution 4 = sharing group. `orgc_uuid` + `sharing_group_uuid`
			// identify which org shared it and to whom. Hub validates the caller
			// matches orgc_uuid via API key.
			distribution: input.sharingGroupUuid ? "4" : "1",
			orgc_uuid: input.orgUuid,
			sharing_group_uuid: input.sharingGroupUuid,
			Tag: [
				{ name: 'type:"OSINT"' },
				{ name: 'tlp:"amber"' },
				{ name: 'misp-galaxy:mitre-attack-pattern="T1566"' },
				{ name: "phishing" },
			],
			Attribute: attrs,
		},
	};
}
