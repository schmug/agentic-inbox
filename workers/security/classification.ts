// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * LLM-based content classification. One structured-output call per email.
 *
 * Tool-using agent triage (fetchUrlPreview, getSenderHistory, etc.) is layered
 * on later — see `workers/security/tools.ts` (added in a follow-up milestone).
 * The synchronous pipeline keeps latency bounded by avoiding tool loops here.
 */

import { DEFAULT_CLASSIFIER_MODEL } from "../../shared/mailbox-settings";
import { stripHtmlToText } from "../lib/email-helpers";
import type { AuthVerdict } from "./auth";

export type ClassificationLabel =
	| "safe"
	| "spam"
	| "phishing"
	| "bec"
	| "suspicious"
	/**
	 * The classifier hit a hard timeout / AbortError before producing a
	 * verdict. Distinct from `suspicious` (which is also used for parse
	 * failures and "model returned garbage" — both still fail-closed).
	 *
	 * Per the narrowed Rule 5 ("Fail closed on LLM timeouts") in the security
	 * spec: only the timeout/AbortError path is allowed to skip its
	 * contribution. Parse-fail and label-not-in-enum paths still fail-closed
	 * to `suspicious`. See `scoreClassification` below for the consumer side.
	 *
	 * Issue: https://github.com/schmug/PhishSOC/issues/28
	 */
	| "unavailable";

export interface ClassificationResult {
	label: ClassificationLabel;
	confidence: number;
	reasoning: string;
}

const SYSTEM_PROMPT = `You are an email security classifier. Classify the email into exactly ONE label and return a confidence and short reasoning.

Labels:
- safe: a normal email (newsletter, personal, business correspondence, automated transactional)
- spam: unsolicited bulk/marketing content with no malicious intent
- phishing: credential theft, fake login, malicious link, impersonates a known brand or service
- bec: business email compromise — impersonates an executive, vendor, colleague to request wire transfer / gift cards / changes to banking details
- suspicious: worrying signals but not clearly malicious; err here instead of safe when in doubt

Return STRICT JSON in this exact shape:
{"label": "safe"|"spam"|"phishing"|"bec"|"suspicious", "confidence": 0.0-1.0, "reasoning": "one short sentence"}

No prose, no code fences, no preamble — just the JSON object.`;

export interface ClassifyInput {
	subject: string;
	sender: string;
	bodyHtml: string;
	auth: AuthVerdict;
}

/**
 * Test-only seam: implementations can be injected via `__setClassifier` to
 * bypass the Workers AI call. This is NOT part of the runtime contract and
 * must not be used from production code paths. Tests reset the override to
 * `null` on teardown.
 */
export type ClassifierImpl = (ai: Ai, input: ClassifyInput) => Promise<ClassificationResult>;
let overrideClassifier: ClassifierImpl | null = null;
export function __setClassifier(impl: ClassifierImpl | null) {
	overrideClassifier = impl;
}

/**
 * True if the error is the hard 5s timeout sentinel from the `Promise.race`
 * below, or a Workers-AI / fetch AbortError.
 *
 * The distinction matters: per Rule 5 of the security spec (narrowed by
 * issue #28), only the timeout/abort path is treated as "I never heard back"
 * and skips its contribution. Other thrown errors (binding misconfigured,
 * network 500, JSON-parse-fail inside `parseClassifierOutput`) still
 * fail-closed to `suspicious`.
 */
function isClassifierTimeout(e: unknown): boolean {
	if (!(e instanceof Error)) return false;
	if (e.message === "classify-timeout") return true;
	// Fetch / Workers-AI propagated abort. `name` covers both the Web
	// Streams AbortError and Node's. `code === "ERR_ABORTED"` is the
	// undici signal.
	if (e.name === "AbortError") return true;
	if ((e as { code?: string }).code === "ERR_ABORTED") return true;
	return false;
}

export async function classifyEmail(
	ai: Ai,
	input: ClassifyInput,
	options: { model?: string; skipOnTimeout?: boolean } = {},
): Promise<ClassificationResult> {
	const plain = stripHtmlToText(input.bodyHtml || "").slice(0, 4000);
	const userMessage = `SENDER: ${input.sender}
AUTH: spf=${input.auth.spf} dkim=${input.auth.dkim} dmarc=${input.auth.dmarc}
SUBJECT: ${input.subject || "(no subject)"}

BODY:
${plain}`;

	const model = options.model?.trim() || DEFAULT_CLASSIFIER_MODEL;
	// Default to TRUE: skip-on-timeout is the new behavior. A mailbox that
	// explicitly opts out via `classification.skip_on_timeout: false` gets
	// the legacy fail-closed-suspicious-on-timeout behavior for backward
	// compat. See issue #28 (narrowing of "fail closed on LLM timeouts").
	const skipOnTimeout = options.skipOnTimeout ?? true;

	try {
		// The override seam runs INSIDE the try so tests can simulate a
		// timeout/AbortError by throwing from the injected classifier and
		// exercise the production catch-block discrimination logic.
		if (overrideClassifier) {
			return await overrideClassifier(ai, input);
		}

		const response = (await Promise.race([
			ai.run(
				model as Parameters<typeof ai.run>[0],
				{
					messages: [
						{ role: "system", content: SYSTEM_PROMPT },
						{ role: "user", content: userMessage },
					],
					max_tokens: 200,
					temperature: 0,
				},
			),
			new Promise((_, reject) =>
				setTimeout(() => reject(new Error("classify-timeout")), 5000),
			),
		])) as { response?: string };

		return parseClassifierOutput(response?.response ?? "");
	} catch (e) {
		const message = (e as Error).message;
		if (isClassifierTimeout(e) && skipOnTimeout) {
			// Rule 5 narrowed (issue #28): timeout/abort no longer fails closed
			// to `suspicious`. Instead the classifier signals "unavailable" and
			// `scoreClassification` contributes 0 to the score with an
			// `llm_unavailable` reason. Other pipeline stages (auth, URLs,
			// reputation, intel) still produce a verdict — the LLM is one
			// signal among many. The "downstream only tightens" invariant is
			// preserved: this path does not relax a real classifier verdict, it
			// only opts the classifier out of contributing on transient outage.
			console.warn("classifyEmail timeout — skipping classifier contribution:", message);
			return { label: "unavailable", confidence: 0, reasoning: "classifier timeout" };
		}
		// Fail closed: unparsable / non-timeout failures → suspicious.
		// We do NOT quarantine solely on classifier failure; the verdict
		// aggregator combines with auth / URL / reputation signals.
		console.error("classifyEmail failed:", message);
		return { label: "suspicious", confidence: 0.3, reasoning: "classifier unavailable" };
	}
}

function parseClassifierOutput(raw: string): ClassificationResult {
	const trimmed = raw.trim();
	// Try to locate the first { ... } block if the model wrapped it.
	const match = trimmed.match(/\{[\s\S]*\}/);
	if (!match) {
		return { label: "suspicious", confidence: 0.3, reasoning: "classifier output not JSON" };
	}
	try {
		const obj = JSON.parse(match[0]);
		const label = normalizeLabel(obj.label);
		const confidence = typeof obj.confidence === "number"
			? Math.max(0, Math.min(1, obj.confidence))
			: 0.5;
		const reasoning = typeof obj.reasoning === "string" ? obj.reasoning.slice(0, 500) : "";
		return { label, confidence, reasoning };
	} catch {
		return { label: "suspicious", confidence: 0.3, reasoning: "classifier output malformed" };
	}
}

function normalizeLabel(raw: unknown): ClassificationLabel {
	if (typeof raw !== "string") return "suspicious";
	const s = raw.toLowerCase().trim();
	if (s === "safe" || s === "spam" || s === "phishing" || s === "bec" || s === "suspicious") {
		return s;
	}
	return "suspicious";
}

export function scoreClassification(result: ClassificationResult): { score: number; reasons: string[] } {
	// `unavailable` (issue #28 / Rule 5 narrowed): the classifier hit a
	// timeout/AbortError. Contribute 0 to the score and tag the verdict so
	// operators can see why the classifier didn't weigh in. Other scorers
	// are NOT inflated to compensate — the LLM is one signal among many,
	// and a clean inbound that scores well on auth + URLs + reputation +
	// intel still reaches `allow`.
	if (result.label === "unavailable") {
		return { score: 0, reasons: ["llm_unavailable"] };
	}
	const map: Record<Exclude<ClassificationLabel, "unavailable">, number> = {
		safe: 0, spam: 20, suspicious: 30, bec: 45, phishing: 50,
	};
	const base = map[result.label];
	// Scale slightly by confidence so low-confidence high-severity labels
	// don't slam the score; high-confidence safe stays at zero.
	const scaled = Math.round(base * (0.5 + 0.5 * result.confidence));
	const reasons = result.label === "safe"
		? []
		: [`classifier: ${result.label} (${Math.round(result.confidence * 100)}%)`];
	return { score: scaled, reasons };
}
