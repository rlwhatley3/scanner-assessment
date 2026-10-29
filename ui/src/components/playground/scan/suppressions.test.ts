import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { expiryBounds, expiryFromDate } from "./suppressions.ts";

describe("expiryBounds", () => {
  it("runs from tomorrow to a day inside the 365-day limit, starting 30 days out", () => {
    const now = new Date(2026, 0, 31, 15, 0);
    assert.deepEqual(expiryBounds(now), {
      min: "2026-02-01",
      max: "2027-01-30",
      initial: "2026-03-02",
    });
  });
});

describe("expiryFromDate", () => {
  it("lasts through the end of the picked local day", () => {
    const expiry = new Date(expiryFromDate("2026-03-02"));
    assert.equal(expiry.getFullYear(), 2026);
    assert.equal(expiry.getMonth(), 2);
    assert.equal(expiry.getDate(), 2);
    assert.equal(expiry.getHours(), 23);
    assert.equal(expiry.getMinutes(), 59);
  });
});
