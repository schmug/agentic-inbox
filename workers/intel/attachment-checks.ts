// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0

/**
 * Filename / MIME-type heuristics for email attachments.
 *
 * These checks are PURE — no I/O, no Workers bindings — so they can be
 * exercised from vitest without mocks and called from both the sync
 * pipeline (for the extension/MIME mismatch, which is cheap) and the
 * async deep-scan (for the full multi-signal verdict).
 *
 * They do NOT replace antivirus. They catch the low-hanging-fruit delivery
 * patterns that malware authors have used for decades: risky extensions,
 * extension/MIME mismatches, and double-extensions designed to hide the
 * dangerous part behind a friendlier-looking suffix.
 */

export interface AttachmentInfo {
	filename: string;
	mimetype: string;
	size: number;
}

export interface AttachmentVerdict {
	/** 0..100 — higher is more suspicious. */
	score: number;
	flags: AttachmentFlag[];
	/** Short human-readable explanation, at most 3 flags joined. */
	explanation: string;
}

export type AttachmentFlag =
	| "dangerous_extension"
	| "macro_enabled_office"
	| "double_extension"
	| "extension_mime_mismatch"
	| "suspicious_archive_name"
	| "executable_in_archive_name"
	| "encrypted_archive"
	| "zero_byte";

/**
 * Optional pre-computed content signals. `scoreAttachment` itself does NOT
 * read bytes — it only inspects filename/MIME. Byte-level checks (e.g.
 * detecting a password-protected ZIP via local-file-header GP flag) happen
 * in the async deep-scan path where fetching bytes from R2 is affordable;
 * the result is passed here so the verdict lives in one place.
 */
export interface AttachmentContentSignals {
	/** True when `detectEncryptedArchive` found an encryption flag set. */
	encryptedArchive?: boolean;
}

/** Always-block extensions. Executable on the user's OS or a script host. */
const DANGEROUS_EXTENSIONS = new Set([
	// Windows executables
	"exe", "scr", "com", "pif", "cpl", "msi", "msp", "mst", "bat", "cmd",
	"vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "psm1", "hta", "lnk",
	"reg", "scf", "jar", "application", "gadget",
	// macOS-y
	"dmg", "pkg", "command", "app",
	// Linux-y that are sometimes sent as attachments
	"deb", "rpm",
	// Installer scripts
	"appx", "appxbundle",
]);

/** Office formats that support macros — not blocked, but high scrutiny. */
const MACRO_OFFICE_EXTENSIONS = new Set([
	"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
]);

/** Archive formats — flagged when their filename advertises an executable inside. */
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "tar", "gz", "tgz", "iso", "img"]);

/**
 * Canonical mime-type → set of acceptable extensions.
 * Used for mismatch detection, not allow-listing. Missing entries mean
 * "don't assert a match" rather than "reject unseen types".
 */
const MIME_EXT_MAP: Record<string, string[]> = {
	"application/pdf": ["pdf"],
	"image/png": ["png"],
	"image/jpeg": ["jpg", "jpeg"],
	"image/gif": ["gif"],
	"image/webp": ["webp"],
	"image/svg+xml": ["svg"],
	"text/plain": ["txt", "log", "md"],
	"text/html": ["html", "htm"],
	"text/csv": ["csv"],
	"application/zip": ["zip"],
	"application/x-rar-compressed": ["rar"],
	"application/x-7z-compressed": ["7z"],
	"application/msword": ["doc"],
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
	"application/vnd.ms-excel": ["xls"],
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
	"application/vnd.ms-powerpoint": ["ppt"],
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": ["pptx"],
};

/** Final extension (lowercased), or empty string if none. */
export function finalExtension(filename: string): string {
	const clean = filename.toLowerCase().trim();
	const idx = clean.lastIndexOf(".");
	if (idx < 0 || idx === clean.length - 1) return "";
	return clean.slice(idx + 1);
}

/** Second-to-last extension, used to detect `.pdf.exe` disguises. */
function penultimateExtension(filename: string): string {
	const clean = filename.toLowerCase().trim();
	const last = clean.lastIndexOf(".");
	if (last <= 0) return "";
	const stem = clean.slice(0, last);
	const prev = stem.lastIndexOf(".");
	if (prev < 0) return "";
	return stem.slice(prev + 1);
}

/**
 * Score + flag a single attachment.
 *
 * This function itself does NOT read file contents — it only inspects the
 * filename and declared MIME. Byte-level signals (like a password-protected
 * ZIP detected via `detectEncryptedArchive`) are computed separately by the
 * async deep-scan and handed in via `signals`. Keeping the content read
 * out of this function lets the same code path serve both the sync pipeline
 * (where we don't pay for R2 reads) and deep-scan.
 *
 * The score is a *contribution* to the email's overall suspicion score —
 * call sites decide how to weight it (the async deep-scan aggregates per
 * email, cap at 30 so attachments can't single-handedly quarantine).
 */
export function scoreAttachment(
	info: AttachmentInfo,
	signals?: AttachmentContentSignals,
): AttachmentVerdict {
	const flags: AttachmentFlag[] = [];
	let score = 0;

	const last = finalExtension(info.filename);
	const prev = penultimateExtension(info.filename);
	const mime = info.mimetype.toLowerCase();

	if (info.size === 0) {
		flags.push("zero_byte");
		score += 5; // weak signal, but zero-byte attachments are rarely legitimate
	}

	if (DANGEROUS_EXTENSIONS.has(last)) {
		flags.push("dangerous_extension");
		score += 40;
	}

	if (MACRO_OFFICE_EXTENSIONS.has(last)) {
		flags.push("macro_enabled_office");
		score += 20;
	}

	// Classic "invoice.pdf.exe" / "report.docx.js" — penultimate extension
	// is a common "safe" one while the final is dangerous. Flag both on
	// dangerous final and on mismatched penultimate.
	if (prev && isLikelyPenultimateCover(prev) && last !== prev) {
		flags.push("double_extension");
		score += 15;
	}

	// MIME/extension mismatch: declared MIME says one thing, filename
	// extension says another. We only flag when the MIME is one we have
	// a canonical mapping for — missing map entries pass silently so we
	// don't flood on exotic-but-valid types.
	const expected = MIME_EXT_MAP[mime];
	if (expected && last && !expected.includes(last)) {
		flags.push("extension_mime_mismatch");
		score += 15;
	}

	// Content-level: encrypted archive (zip/rar/…). An encrypted archive
	// delivered over email is a well-established malware delivery pattern
	// (Emotet, Qakbot): the password arrives in the message body so the
	// recipient can open it, while the encryption defeats antivirus
	// scanning at the gateway. Scored between `macro_enabled_office` (20)
	// and `dangerous_extension` (40) to reflect that risk.
	if (signals?.encryptedArchive) {
		flags.push("encrypted_archive");
		score += 25;
	}

	// Archive whose filename mentions an executable payload. Cheap check
	// that catches the common `invoice_exe.zip` or `report(exe).zip`
	// spam/phish patterns without unpacking.
	if (ARCHIVE_EXTENSIONS.has(last)) {
		const lower = info.filename.toLowerCase();
		// Allow underscore/dot/dash/parens as segment separators, not just
		// \b (which treats `_exe` as a single word).
		if (/(?:^|[^a-z0-9])(exe|scr|bat|cmd|vbs|js|ps1|hta|lnk)(?:[^a-z0-9]|$)/.test(lower)) {
			flags.push("executable_in_archive_name");
			score += 10;
		} else if (
			!signals?.encryptedArchive &&
			/(?:^|[^a-z0-9])(invoice|receipt|payment|shipment|tracking)(?:[^a-z0-9]|$)/.test(lower)
		) {
			// Commercial-bait archive — not blocked, just nudged upward.
			// Subsumed by the stronger `encrypted_archive` signal when both
			// apply (e.g. `invoice.zip` that is password-protected); we skip
			// the bait nudge so the reason string in the UI isn't redundant.
			flags.push("suspicious_archive_name");
			score += 5;
		}
	}

	score = Math.max(0, Math.min(100, score));
	const explanation = flags.slice(0, 3).join(", ") || "no notable signals";
	return { score, flags, explanation };
}

// ── Content-based detection ────────────────────────────────────────
//
// These helpers DO read raw bytes and are called from the async deep-scan
// with a size-capped buffer (the first ~32KB of the attachment). Kept here
// so the flag that describes the outcome lives next to the detector that
// produces it.

/** Maximum bytes we'll scan looking for an archive signature. Guards against
 *  runaway loops on large buffers and keeps the work proportional to what
 *  the deep-scan actually fetches from R2. */
const ARCHIVE_SCAN_WINDOW = 32 * 1024;

/** Per-format minimum buffer lengths. Anything shorter can't carry enough
 *  structure to decide safely. A ZIP local-file-header is 30 bytes fixed;
 *  a RAR4 main header is 20 bytes past the 7-byte magic. */
const ZIP_MIN_LEN = 30;
const RAR4_MIN_LEN = 7 + 13;
/** Lower bound below which any archive buffer is junk. */
const ARCHIVE_MIN_LEN = Math.min(ZIP_MIN_LEN, RAR4_MIN_LEN);

/**
 * Detect whether an archive's header advertises encryption / password
 * protection. Reads ONLY the bytes we have (caller typically passes a
 * partial R2 read of 32KB) — never decrypts or decompresses.
 *
 * Supported:
 *   - ZIP: local-file-header general-purpose flag bit 0. Scans the window
 *     for the signature rather than assuming offset 0, so self-extracting
 *     archives with an EXE stub prefix are still detected. NOTE: Central
 *     Directory Encryption (PKZIP SES strong encryption) is NOT detected —
 *     the CD lives at end-of-file which is outside our window. We accept
 *     this false-negative rather than over-fetch.
 *   - RAR4: MAIN_HEAD (HEAD_TYPE 0x73) MHD_PASSWORD flag bit 0x0080, AND
 *     any file block (HEAD_TYPE 0x74) with LHD_PASSWORD bit 0x0004. Flag
 *     values are per the RAR technote / unrar source.
 *   - RAR5: not yet implemented — header record walking is deferred.
 *     Returns false. (Parse failures on a RAR5-signature buffer are safe
 *     false-negatives, not throws.)
 *   - 7z: not implemented. Header encryption detection requires walking
 *     SignatureHeader → StartHeader streams; deferred to avoid
 *     false-positives on legitimate 7z archives.
 *
 * Never throws. A false-negative is strictly preferable to a false-positive
 * here — we'd rather miss a malicious archive than block a legitimate one.
 */
export function detectEncryptedArchive(bytes: Uint8Array, ext: string): boolean {
	if (!bytes || bytes.length < ARCHIVE_MIN_LEN) return false;
	const lower = ext.toLowerCase();

	if (lower === "zip") return detectEncryptedZip(bytes);
	if (lower === "rar") return detectEncryptedRar(bytes);
	// 7z and anything else: conservative false.
	return false;
}

function detectEncryptedZip(bytes: Uint8Array): boolean {
	if (bytes.length < ZIP_MIN_LEN) return false;
	// Find the first local-file-header signature (0x04034b50, little-endian
	// on disk => bytes 50 4B 03 04) within the scan window. SFX archives
	// prepend a native executable stub, so we can't assume offset 0.
	const limit = Math.min(bytes.length - 30, ARCHIVE_SCAN_WINDOW);
	for (let i = 0; i <= limit; i++) {
		if (
			bytes[i] === 0x50 &&
			bytes[i + 1] === 0x4b &&
			bytes[i + 2] === 0x03 &&
			bytes[i + 3] === 0x04
		) {
			// General-purpose bit flag is a 16-bit LE field at offset +6.
			// Bit 0 = "file is encrypted" (PKZIP 2.0+). AES-encrypted zips
			// use AE-x extra-field 0x9901 but STILL set bit 0, so this
			// single check covers both classical and AES encryption for
			// local-file-header encryption.
			const gpFlag = bytes[i + 6] | (bytes[i + 7] << 8);
			return (gpFlag & 0x0001) !== 0;
		}
	}
	return false;
}

function detectEncryptedRar(bytes: Uint8Array): boolean {
	if (bytes.length < RAR4_MIN_LEN) return false;
	// RAR4 magic: `Rar!\x1a\x07\x00`. RAR5 magic ends with `\x01\x00`.
	// We detect RAR4 specifically; RAR5 is deferred.
	const magicRar4 = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
	for (let i = 0; i < magicRar4.length; i++) {
		if (bytes[i] !== magicRar4[i]) return false;
	}

	// Walk the block headers. Each block begins with: CRC(2) TYPE(1) FLAGS(2)
	// SIZE(2) and optionally ADD_SIZE(4) when FLAGS & LONG_BLOCK (0x8000).
	// We stop after a bounded number of blocks or when SIZE looks invalid —
	// this is a detector, not a parser, so giving up is always safe.
	let offset = magicRar4.length;
	const MAX_BLOCKS = 32;
	for (let block = 0; block < MAX_BLOCKS && offset + 7 <= bytes.length; block++) {
		const type = bytes[offset + 2];
		const flags = bytes[offset + 3] | (bytes[offset + 4] << 8);
		const size = bytes[offset + 5] | (bytes[offset + 6] << 8);

		if (type === 0x73) {
			// MAIN_HEAD — archive-level password flag.
			if ((flags & 0x0080) !== 0) return true;
		} else if (type === 0x74) {
			// FILE_HEAD — per-file password flag.
			if ((flags & 0x0004) !== 0) return true;
		}

		if (size < 7) return false; // malformed — stop rather than loop
		let advance = size;
		if ((flags & 0x8000) !== 0 && offset + 11 <= bytes.length) {
			// LONG_BLOCK adds a 4-byte ADD_SIZE after HEAD_SIZE.
			const addSize =
				bytes[offset + 7] |
				(bytes[offset + 8] << 8) |
				(bytes[offset + 9] << 16) |
				(bytes[offset + 10] << 24);
			if (addSize > 0) advance += addSize;
		}
		if (advance <= 0 || advance > ARCHIVE_SCAN_WINDOW) return false;
		offset += advance;
	}
	return false;
}

/**
 * Per-email aggregation: roll up individual attachment verdicts into a
 * single score capped at 30 so attachments can contribute meaningfully
 * to quarantine but never dominate the aggregate on their own.
 */
export function aggregateAttachmentSignals(
	verdicts: AttachmentVerdict[],
): { score: number; flags: AttachmentFlag[]; reasons: string[] } {
	const flags = new Set<AttachmentFlag>();
	const reasons: string[] = [];
	let highest = 0;
	for (const v of verdicts) {
		for (const f of v.flags) flags.add(f);
		if (v.score > highest) highest = v.score;
		if (v.flags.length > 0) reasons.push(`attachment: ${v.explanation}`);
	}
	return {
		score: Math.min(30, highest),
		flags: [...flags],
		// De-duplicated explanation lines, capped at a couple entries for brevity.
		reasons: dedupe(reasons).slice(0, 2),
	};
}

function dedupe(items: string[]): string[] {
	return [...new Set(items)];
}

/**
 * Penultimate extensions that get abused as "cover" in double-extension
 * tricks. Constrained to common document / media types — we don't want
 * legitimate files like `archive.tar.gz` to flag.
 */
function isLikelyPenultimateCover(ext: string): boolean {
	return ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png"].includes(ext);
}
