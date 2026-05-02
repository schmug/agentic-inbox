import { describe, expect, it } from "vitest";
import {
	emptyVerdict,
	extractReceivedFromIp,
	parseAuthResults,
	scoreAuth,
} from "../../workers/security/auth";

function header(name: string, value: string) {
	return { key: name, value };
}

describe("parseAuthResults", () => {
	it("returns all-none when no Authentication-Results header present", () => {
		expect(parseAuthResults([header("from", "a@b.com")])).toEqual(emptyVerdict());
	});

	it("returns all-none when rawHeaders is not an array", () => {
		expect(parseAuthResults(null)).toEqual(emptyVerdict());
		expect(parseAuthResults(undefined)).toEqual(emptyVerdict());
		expect(parseAuthResults("not-an-array")).toEqual(emptyVerdict());
	});

	it("parses a standard gmail-style Authentication-Results header", () => {
		const verdict = parseAuthResults([
			header(
				"Authentication-Results",
				"mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com",
			),
		]);
		expect(verdict).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass", authservId: "mx.google.com" });
	});

	it("captures softfail/fail/temperror/permerror", () => {
		const verdict = parseAuthResults([
			header(
				"Authentication-Results",
				"srv1; spf=softfail smtp.mailfrom=x; dkim=fail; dmarc=temperror",
			),
		]);
		expect(verdict).toMatchObject({ spf: "softfail", dkim: "fail", dmarc: "temperror" });
	});

	it("is case-insensitive on header key and result values", () => {
		const verdict = parseAuthResults([
			header("AUTHENTICATION-RESULTS", "authserv-x; SPF=Pass; DKIM=Fail; DMARC=None"),
		]);
		expect(verdict).toMatchObject({ spf: "pass", dkim: "fail", dmarc: "none", authservId: "authserv-x" });
	});

	it("first-verdict-wins across duplicate Authentication-Results headers", () => {
		// Multiple Authentication-Results headers can appear when mail traverses
		// several verifiers. We trust the first (outermost-recorded) result so a
		// downstream relay cannot override an upstream failure verdict.
		const verdict = parseAuthResults([
			header("Authentication-Results", "inner; spf=fail; dkim=fail; dmarc=fail"),
			header("Authentication-Results", "outer; spf=pass; dkim=pass; dmarc=pass"),
		]);
		expect(verdict).toMatchObject({ spf: "fail", dkim: "fail", dmarc: "fail", authservId: "inner" });
	});

	it("ignores irrelevant headers", () => {
		const verdict = parseAuthResults([
			header("DKIM-Signature", "v=1; a=rsa-sha256; dkim=pass"),
			header("Received-SPF", "pass"),
		]);
		expect(verdict).toEqual(emptyVerdict());
	});

	it("captures authserv-id when no method results are present", () => {
		const verdict = parseAuthResults([
			header("Authentication-Results", "auth.example.com; none"),
		]);
		expect(verdict.authservId).toBe("auth.example.com");
	});
});

describe("parseAuthResults — authserv-id gating", () => {
	// The forgery threat: an attacker-controlled upstream mail server can
	// inject its own Authentication-Results header claiming pass results
	// before sending. Cloudflare Email Routing preserves such headers, so a
	// parser that trusts any Authentication-Results header would accept
	// forged verdicts. These tests pin the defensive behaviour.

	it("ignores headers whose authserv-id is not on the trusted list", () => {
		const v = parseAuthResults(
			[
				header("Authentication-Results", "attacker.example; spf=pass; dkim=pass; dmarc=pass"),
				header("Authentication-Results", "mx.cloudflare.net; spf=fail; dkim=fail; dmarc=fail"),
			],
			{ trustedAuthservIds: ["mx.cloudflare.net"] },
		);
		expect(v).toMatchObject({ spf: "fail", dkim: "fail", dmarc: "fail", authservId: "mx.cloudflare.net", trusted: true });
	});

	it("matches trusted authserv-id as a dotted suffix", () => {
		const v = parseAuthResults(
			[header("Authentication-Results", "mx5.google.com; spf=pass; dkim=pass; dmarc=pass")],
			{ trustedAuthservIds: ["google.com"] },
		);
		expect(v).toMatchObject({ spf: "pass", trusted: true });
	});

	it("returns all-none when no trusted header is present (prefers silence over forged-pass)", () => {
		const v = parseAuthResults(
			[header("Authentication-Results", "attacker.example; spf=pass; dkim=pass; dmarc=pass")],
			{ trustedAuthservIds: ["mx.cloudflare.net"] },
		);
		expect(v).toEqual(emptyVerdict());
	});

	it("treats an empty trusted list as 'trust any' (back-compat)", () => {
		const v = parseAuthResults(
			[header("Authentication-Results", "anywhere; spf=pass; dkim=pass; dmarc=pass")],
			{ trustedAuthservIds: [] },
		);
		expect(v).toMatchObject({ spf: "pass", dkim: "pass", dmarc: "pass" });
	});

	it("preserves 'first set wins' — legitimate dkim=none is not overwritten by later headers", () => {
		// Regression: earlier versions used the string 'none' as both the
		// value and the "not yet set" sentinel, so a first header with
		// `dkim=none` let any subsequent header overwrite it — including
		// an attacker-controlled one when gating was off.
		const v = parseAuthResults([
			header("Authentication-Results", "inner; spf=pass; dkim=none; dmarc=pass"),
			header("Authentication-Results", "outer; spf=fail; dkim=pass; dmarc=fail"),
		]);
		expect(v).toMatchObject({ spf: "pass", dkim: "none", dmarc: "pass" });
	});
});

describe("scoreAuth", () => {
	it("scores a clean pass as a net-negative (credit)", () => {
		const { score } = scoreAuth({ spf: "pass", dkim: "pass", dmarc: "pass" });
		expect(score).toBe(-10);
	});

	it("scores a DMARC fail as suspicious", () => {
		const { score, reasons } = scoreAuth({ spf: "pass", dkim: "pass", dmarc: "fail" });
		expect(score).toBeGreaterThanOrEqual(20);
		expect(reasons.join(" ")).toMatch(/DMARC/i);
	});

	it("caps multi-fail contribution at 30 (before DMARC-pass credit)", () => {
		const { score } = scoreAuth({ spf: "fail", dkim: "fail", dmarc: "fail" });
		expect(score).toBe(30);
	});

	it("scores SPF softfail identically to SPF fail (treats both as suspicious)", () => {
		const softfail = scoreAuth({ spf: "softfail", dkim: "none", dmarc: "none" });
		const fail = scoreAuth({ spf: "fail", dkim: "none", dmarc: "none" });
		expect(softfail.score).toBe(fail.score);
	});

	it("returns zero for all-none (no auth headers present)", () => {
		const { score } = scoreAuth(emptyVerdict());
		expect(score).toBe(0);
	});
});

describe("extractReceivedFromIp", () => {
	it("returns undefined when there are no Received headers", () => {
		expect(extractReceivedFromIp([header("Authentication-Results", "x; spf=pass")])).toBeUndefined();
	});

	it("returns undefined when rawHeaders is not an array", () => {
		expect(extractReceivedFromIp(null)).toBeUndefined();
		expect(extractReceivedFromIp(undefined)).toBeUndefined();
		expect(extractReceivedFromIp("not-an-array")).toBeUndefined();
	});

	it("extracts an external IPv4 from a bracketed RFC 5321 Received line", () => {
		const headers = [
			header(
				"Received",
				"from mail.example.com (mail.example.com [203.0.113.42]) by mx.cloudflare.com",
			),
		];
		expect(extractReceivedFromIp(headers)).toBe("203.0.113.42");
	});

	it("returns the FIRST external IP (most-recent external hop) when multiple Received lines present", () => {
		// PostalMime preserves header order: most-recent hop first.
		const headers = [
			header(
				"Received",
				"from inbound.cloudflare.net (inbound.cloudflare.net [10.0.0.5]) by mx",
			),
			header(
				"Received",
				"from sender.example.com (sender.example.com [198.51.100.7]) by inbound.cloudflare.net",
			),
			header(
				"Received",
				"from origin.attacker.example (origin.attacker.example [203.0.113.99]) by sender.example.com",
			),
		];
		// 10.0.0.5 is private and is skipped; the next external hop is 198.51.100.7.
		expect(extractReceivedFromIp(headers)).toBe("198.51.100.7");
	});

	it("skips RFC1918 private IPs (10/8, 172.16/12, 192.168/16)", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from internal (internal [10.1.2.3]) by mx"),
				header("Received", "from public (public [203.0.113.1]) by internal"),
			]),
		).toBe("203.0.113.1");
		expect(
			extractReceivedFromIp([
				header("Received", "from internal (internal [172.16.0.1]) by mx"),
				header("Received", "from public (public [203.0.113.2]) by internal"),
			]),
		).toBe("203.0.113.2");
		expect(
			extractReceivedFromIp([
				header("Received", "from internal (internal [192.168.1.1]) by mx"),
				header("Received", "from public (public [203.0.113.3]) by internal"),
			]),
		).toBe("203.0.113.3");
	});

	it("skips loopback (127/8) and link-local (169.254/16)", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from local (local [127.0.0.1]) by mx"),
				header("Received", "from external (external [203.0.113.4]) by local"),
			]),
		).toBe("203.0.113.4");
		expect(
			extractReceivedFromIp([
				header("Received", "from ll (ll [169.254.10.10]) by mx"),
				header("Received", "from external (external [203.0.113.5]) by ll"),
			]),
		).toBe("203.0.113.5");
	});

	it("returns undefined when every Received line is internal", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from a (a [10.0.0.1]) by b"),
				header("Received", "from c (c [192.168.1.1]) by d"),
			]),
		).toBeUndefined();
	});

	it("handles bare-bracket IPv4 without a parenthesized hostname", () => {
		expect(
			extractReceivedFromIp([
				header("Received", "from sender [203.0.113.55] by mx"),
			]),
		).toBe("203.0.113.55");
	});
});
