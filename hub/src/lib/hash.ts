// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * SHA-256 hex digest. Used for API-key storage and invite-token hashing so
 * a leaked D1 snapshot doesn't allow impersonation of contributors.
 */
export async function sha256(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const hash = await crypto.subtle.digest("SHA-256", data);
	return Array.from(new Uint8Array(hash))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/** 43 random base64url chars (≈256 bits of entropy). */
export function generateSecret(): string {
	const buf = new Uint8Array(32);
	crypto.getRandomValues(buf);
	return btoa(String.fromCharCode(...buf))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}
