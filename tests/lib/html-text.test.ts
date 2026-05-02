import { describe, expect, it } from "vitest";
import { htmlToPlainText } from "shared/html-text";

describe("htmlToPlainText", () => {
	it("returns empty string for empty input", () => {
		expect(htmlToPlainText("")).toBe("");
		expect(htmlToPlainText(undefined as unknown as string)).toBe("");
	});

	it("strips simple tags and collapses whitespace", () => {
		expect(htmlToPlainText("<p>Hello <b>world</b></p>")).toBe("Hello world");
	});

	it("drops <script> content even with attributes containing >", () => {
		const input = '<script type=">"]>alert(1)</script>after';
		expect(htmlToPlainText(input)).toBe("after");
	});

	it("drops <script> content terminated by `</script foo>` (CodeQL js/bad-tag-filter)", () => {
		const input = "before<script>alert(1)</script foo>after";
		expect(htmlToPlainText(input)).toBe("before after");
	});

	it("drops <style> content with attributes containing >", () => {
		const input = '<style media=">">body{color:red}</style>visible';
		expect(htmlToPlainText(input)).toBe("visible");
	});

	it("preserves attribute text without leaking tag contents", () => {
		// Naïve /<[^>]*>/g would emit `="x">` as text. Tokenizer must not.
		expect(htmlToPlainText('<a href="x">link</a>')).toBe("link");
	});

	it("ignores `<` not followed by a tag name (literal text)", () => {
		expect(htmlToPlainText("a < b and c > d")).toBe("a < b and c > d");
	});

	it("decodes named entities exactly once (no double-unescape)", () => {
		// `&amp;lt;` should decode to `&lt;` (literal), not `<`. The previous
		// regex pipeline did the double-decode that CodeQL flagged.
		expect(htmlToPlainText("&amp;lt;tag&amp;gt;")).toBe("&lt;tag&gt;");
	});

	it("decodes numeric and hex entities", () => {
		expect(htmlToPlainText("&#39;hi&#39; &#x2014; ok")).toBe("'hi' — ok");
	});

	it("strips HTML comments", () => {
		expect(htmlToPlainText("a<!-- evil -->b")).toBe("a b");
	});

	it("preserves block-level breaks when requested", () => {
		const out = htmlToPlainText("<p>one</p><p>two</p>", {
			preserveLineBreaks: true,
		});
		expect(out).toBe("one\n\ntwo");
	});

	it("turns <br> into a newline when preserveLineBreaks is set", () => {
		const out = htmlToPlainText("line1<br>line2", { preserveLineBreaks: true });
		expect(out).toBe("line1\nline2");
	});

	it("does not execute or leak event-handler attributes", () => {
		const input = '<img src=x onerror="alert(1)">';
		expect(htmlToPlainText(input)).toBe("");
	});

	it("handles unclosed tags without infinite-looping", () => {
		expect(htmlToPlainText("hello <b world")).toBe("hello");
	});
});
