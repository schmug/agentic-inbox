import { describe, expect, it } from "vitest";
import {
	aggregateAttachmentSignals,
	detectEncryptedArchive,
	finalExtension,
	scoreAttachment,
} from "../../workers/intel/attachment-checks";

// ── byte-buffer helpers for the detectEncryptedArchive tests ────────────
//
// These construct minimal-but-valid archive prefixes by hand so the tests
// don't depend on any compression library. We only need enough bytes for
// the header-parsing code to reach an encryption-flag decision.

/** Build a ZIP local-file-header with the given general-purpose flag. */
function zipLocalHeader(gpFlag: number, prefix: Uint8Array = new Uint8Array(0)): Uint8Array {
	const hdr = new Uint8Array(30 + 4); // 30-byte fixed header + 4-byte filename "test"
	const view = new DataView(hdr.buffer);
	view.setUint32(0, 0x04034b50, true); // signature
	view.setUint16(4, 20, true); // version needed
	view.setUint16(6, gpFlag, true); // general purpose flag
	view.setUint16(8, 0, true); // compression method (stored)
	view.setUint16(10, 0, true); // mod time
	view.setUint16(12, 0, true); // mod date
	view.setUint32(14, 0, true); // CRC-32
	view.setUint32(18, 0, true); // compressed size
	view.setUint32(22, 0, true); // uncompressed size
	view.setUint16(26, 4, true); // filename length
	view.setUint16(28, 0, true); // extra length
	// "test" filename bytes
	hdr[30] = 0x74; hdr[31] = 0x65; hdr[32] = 0x73; hdr[33] = 0x74;
	const out = new Uint8Array(prefix.length + hdr.length);
	out.set(prefix, 0);
	out.set(hdr, prefix.length);
	return out;
}

/**
 * Build a RAR4 archive prefix (magic + MARK_HEAD + MAIN_HEAD) with the
 * given main-header flags. MHD_PASSWORD is 0x0080 per the RAR technote
 * and the unrar source (`#define MHD_PASSWORD 0x0080`).
 */
function rar4Prefix(mainFlags: number): Uint8Array {
	const out = new Uint8Array(7 + 13);
	// MARK_HEAD magic: `Rar!\x1a\x07\x00`
	out.set([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00], 0);
	// MAIN_HEAD block at offset 7: CRC(2) + TYPE(1) + FLAGS(2) + SIZE(2) + HighPosAV(2) + PosAV(4)
	const view = new DataView(out.buffer);
	view.setUint16(7, 0x0000, true); // CRC (not validated by our detector)
	out[9] = 0x73; // HEAD_TYPE = MAIN_HEAD
	view.setUint16(10, mainFlags, true); // HEAD_FLAGS
	view.setUint16(12, 13, true); // HEAD_SIZE
	view.setUint16(14, 0, true); // HighPosAV
	view.setUint32(16, 0, true); // PosAV
	return out;
}

describe("detectEncryptedArchive", () => {
	it("returns false for a plain ZIP (GP flag bit 0 = 0)", () => {
		expect(detectEncryptedArchive(zipLocalHeader(0x0000), "zip")).toBe(false);
	});

	it("returns true for an encrypted ZIP (GP flag bit 0 = 1)", () => {
		expect(detectEncryptedArchive(zipLocalHeader(0x0001), "zip")).toBe(true);
	});

	it("returns true for a self-extracting (SFX) encrypted ZIP with an EXE stub prefix", () => {
		// SFX archives prepend an EXE loader — the ZIP local-file-header
		// signature is NOT at offset 0. The detector must scan for it.
		const exeStub = new Uint8Array(2048);
		for (let i = 0; i < exeStub.length; i++) exeStub[i] = (i * 7) & 0xff;
		exeStub[0] = 0x4d; exeStub[1] = 0x5a; // "MZ" DOS header
		expect(detectEncryptedArchive(zipLocalHeader(0x0001, exeStub), "zip")).toBe(true);
	});

	it("returns false for a RAR4 archive with no password", () => {
		expect(detectEncryptedArchive(rar4Prefix(0x0000), "rar")).toBe(false);
	});

	it("returns true for a RAR4 archive with MHD_PASSWORD set", () => {
		expect(detectEncryptedArchive(rar4Prefix(0x0080), "rar")).toBe(true);
	});

	it("returns false for very short / truncated buffers without throwing", () => {
		expect(detectEncryptedArchive(new Uint8Array([1, 2, 3]), "zip")).toBe(false);
		expect(detectEncryptedArchive(new Uint8Array([0x52, 0x61]), "rar")).toBe(false);
	});

	it("returns false for a buffer that contains no archive signature", () => {
		const junk = new Uint8Array(1024);
		for (let i = 0; i < junk.length; i++) junk[i] = 0x20;
		expect(detectEncryptedArchive(junk, "zip")).toBe(false);
		expect(detectEncryptedArchive(junk, "rar")).toBe(false);
	});

	it("returns false for 7z (header-encryption detection not implemented in v1)", () => {
		// 7z signature is `7z\xBC\xAF\x27\x1C`. Header-encryption detection
		// requires walking the StartHeader stream, which is deferred. We
		// document the conservative behaviour: always return false rather
		// than risk false-positives on legit 7z archives.
		const sig = new Uint8Array([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x00, 0x00]);
		expect(detectEncryptedArchive(sig, "7z")).toBe(false);
	});

	it("returns false for non-archive extensions", () => {
		expect(detectEncryptedArchive(zipLocalHeader(0x0001), "pdf")).toBe(false);
	});
});

describe("finalExtension", () => {
	it("returns lowercased extension", () => {
		expect(finalExtension("Report.PDF")).toBe("pdf");
	});
	it("returns empty for extensionless files", () => {
		expect(finalExtension("LICENSE")).toBe("");
	});
	it("ignores trailing dots", () => {
		expect(finalExtension("report.")).toBe("");
	});
	it("handles multi-dot filenames (last wins)", () => {
		expect(finalExtension("archive.tar.gz")).toBe("gz");
	});
});

describe("scoreAttachment", () => {
	it("flags dangerous extensions aggressively", () => {
		const v = scoreAttachment({ filename: "invoice.exe", mimetype: "application/octet-stream", size: 1024 });
		expect(v.flags).toContain("dangerous_extension");
		expect(v.score).toBeGreaterThanOrEqual(40);
	});

	it("flags macro-enabled Office docs", () => {
		const v = scoreAttachment({ filename: "quarterly-report.docm", mimetype: "application/vnd.ms-word.document.macroEnabled.12", size: 2048 });
		expect(v.flags).toContain("macro_enabled_office");
	});

	it("flags the classic invoice.pdf.exe double-extension pattern", () => {
		const v = scoreAttachment({ filename: "invoice.pdf.exe", mimetype: "application/octet-stream", size: 512 });
		expect(v.flags).toContain("dangerous_extension");
		expect(v.flags).toContain("double_extension");
	});

	it("does not flag legitimate archives with `.tar.gz` as double-extension", () => {
		const v = scoreAttachment({ filename: "release.tar.gz", mimetype: "application/gzip", size: 10_000 });
		expect(v.flags).not.toContain("double_extension");
	});

	it("flags MIME/extension mismatches (pdf MIME with .exe extension)", () => {
		const v = scoreAttachment({ filename: "contract.exe", mimetype: "application/pdf", size: 1_000 });
		expect(v.flags).toContain("extension_mime_mismatch");
		expect(v.flags).toContain("dangerous_extension");
	});

	it("does not flag well-known mime/ext matches", () => {
		const v = scoreAttachment({ filename: "photo.png", mimetype: "image/png", size: 10_000 });
		expect(v.flags).toEqual([]);
		expect(v.score).toBe(0);
	});

	it("passes silently on MIME types we don't have a map for", () => {
		const v = scoreAttachment({ filename: "data.bin", mimetype: "application/some-novel-type", size: 2000 });
		expect(v.flags).not.toContain("extension_mime_mismatch");
	});

	it("flags archives whose filename advertises an executable", () => {
		const v = scoreAttachment({ filename: "invoice_exe.zip", mimetype: "application/zip", size: 1000 });
		expect(v.flags).toContain("executable_in_archive_name");
	});

	it("nudges commercial-bait archive names slightly", () => {
		const v = scoreAttachment({ filename: "invoice-123.zip", mimetype: "application/zip", size: 1000 });
		expect(v.flags).toContain("suspicious_archive_name");
		expect(v.score).toBeLessThan(15);
	});

	it("flags zero-byte attachments", () => {
		const v = scoreAttachment({ filename: "empty.pdf", mimetype: "application/pdf", size: 0 });
		expect(v.flags).toContain("zero_byte");
	});

	it("clamps scores to the [0, 100] range", () => {
		const v = scoreAttachment({ filename: "invoice.pdf.exe", mimetype: "application/pdf", size: 0 });
		expect(v.score).toBeLessThanOrEqual(100);
		expect(v.score).toBeGreaterThanOrEqual(0);
	});

	it("flags encrypted_archive when the caller reports a positive content signal", () => {
		const v = scoreAttachment(
			{ filename: "payload.zip", mimetype: "application/zip", size: 10_000 },
			{ encryptedArchive: true },
		);
		expect(v.flags).toContain("encrypted_archive");
		expect(v.score).toBeGreaterThanOrEqual(25);
	});

	it("subsumes the bait-name nudge when an archive is also encrypted (avoids double-count)", () => {
		// `invoice.zip` alone would trigger "suspicious_archive_name" (+5).
		// When it is ALSO encrypted, the bigger signal wins and we skip the
		// nudge so the reason string isn't redundant in the UI.
		const v = scoreAttachment(
			{ filename: "invoice.zip", mimetype: "application/zip", size: 10_000 },
			{ encryptedArchive: true },
		);
		expect(v.flags).toContain("encrypted_archive");
		expect(v.flags).not.toContain("suspicious_archive_name");
	});

	it("does not flag encrypted_archive when the signal is absent/false", () => {
		const plain = scoreAttachment(
			{ filename: "photos.zip", mimetype: "application/zip", size: 10_000 },
			{ encryptedArchive: false },
		);
		expect(plain.flags).not.toContain("encrypted_archive");
		const omitted = scoreAttachment(
			{ filename: "photos.zip", mimetype: "application/zip", size: 10_000 },
		);
		expect(omitted.flags).not.toContain("encrypted_archive");
	});
});

describe("aggregateAttachmentSignals", () => {
	it("caps contribution at 30 so attachments can't dominate", () => {
		const v = aggregateAttachmentSignals([
			scoreAttachment({ filename: "a.exe", mimetype: "application/pdf", size: 0 }),
			scoreAttachment({ filename: "b.docm", mimetype: "x", size: 0 }),
		]);
		expect(v.score).toBeLessThanOrEqual(30);
	});

	it("returns zero when every attachment is clean", () => {
		const v = aggregateAttachmentSignals([
			scoreAttachment({ filename: "photo.png", mimetype: "image/png", size: 10_000 }),
		]);
		expect(v.score).toBe(0);
	});

	it("de-duplicates repeated reasons across attachments", () => {
		const v = aggregateAttachmentSignals([
			scoreAttachment({ filename: "a.exe", mimetype: "application/octet-stream", size: 100 }),
			scoreAttachment({ filename: "b.exe", mimetype: "application/octet-stream", size: 100 }),
		]);
		expect(v.reasons.length).toBeLessThanOrEqual(2);
	});
});
