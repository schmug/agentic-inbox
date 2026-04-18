import { describe, expect, it } from "vitest";
import { scoreOffHours } from "../../workers/security/time-rules";
import type { BusinessHours } from "../../workers/security/settings";

const NY: BusinessHours = {
	timezone: "America/New_York",
	start_hour: 9,
	end_hour: 18,
	weekdays_only: true,
	boost_on_off_hours: true,
};

// 2026-04-20 (Monday) — chosen to avoid DST edges.
const monday9amEt = new Date("2026-04-20T13:00:00Z"); // 09:00 New_York
const monday3amEt = new Date("2026-04-20T07:00:00Z"); // 03:00 New_York
const monday6pmEt = new Date("2026-04-20T22:00:00Z"); // 18:00 New_York (off)
const saturday10amEt = new Date("2026-04-25T14:00:00Z"); // Sat 10:00 New_York

describe("scoreOffHours", () => {
	it("returns zero when business_hours is undefined", () => {
		expect(scoreOffHours(undefined, monday3amEt)).toEqual({ score: 0, reasons: [] });
	});

	it("returns zero when boost_on_off_hours is false", () => {
		expect(scoreOffHours({ ...NY, boost_on_off_hours: false }, monday3amEt)).toEqual({ score: 0, reasons: [] });
	});

	it("returns zero for email delivered inside business hours", () => {
		expect(scoreOffHours(NY, monday9amEt).score).toBe(0);
	});

	it("boosts mail delivered outside the hour window on a weekday", () => {
		const r = scoreOffHours(NY, monday3amEt);
		expect(r.score).toBe(10);
		expect(r.reasons[0]).toMatch(/outside business hours/);
	});

	it("treats end_hour as exclusive — 18:00 itself is off-hours", () => {
		expect(scoreOffHours(NY, monday6pmEt).score).toBe(10);
	});

	it("flags weekend delivery when weekdays_only", () => {
		const r = scoreOffHours(NY, saturday10amEt);
		expect(r.score).toBe(10);
		expect(r.reasons[0]).toMatch(/weekend/);
	});

	it("does not flag weekend delivery when weekdays_only is false", () => {
		const r = scoreOffHours({ ...NY, weekdays_only: false }, saturday10amEt);
		expect(r.score).toBe(0);
	});

	it("returns zero for an invalid timezone (conservative: missing signal is better than wrong signal)", () => {
		const r = scoreOffHours({ ...NY, timezone: "Not/A/Real/Zone" }, monday3amEt);
		expect(r.score).toBe(0);
	});

	it("handles a wrapped (night-shift) window", () => {
		// 22:00 → 06:00. A 3 AM delivery falls inside the window → no boost.
		const nightShift: BusinessHours = { ...NY, start_hour: 22, end_hour: 6, weekdays_only: false };
		expect(scoreOffHours(nightShift, monday3amEt).score).toBe(0);
	});
});
