import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SavedMatch } from "../api.ts";
import { expiryBounds, expiryFromDate, splitSuppressed } from "./suppressions.ts";

function match(id: number, suppressed: boolean): SavedMatch {
  return {
    id,
    ruleId: 1,
    kind: "match",
    violationPretty: "",
    suppression: suppressed ? { id: 9, reason: "Doc example", expiresAt: "" } : null,
    violation: {
      ruleName: "Test rule",
      detectionType: "direct_credential",
      severity: "high",
      confidence: 90,
      placeholderScore: 0,
      location: {
        startByte: 0,
        endByte: 1,
        startLine: 1,
        startColumn: 1,
        endLine: 1,
        endColumn: 2,
      },
      redactedPreview: null,
      whyFlagged: "",
      remediation: "",
      overlapGroup: null,
      inComment: false,
      checksumValid: null,
    },
  };
}

describe("splitSuppressed", () => {
  it("keeps every finding, split by whether a suppression covers it", () => {
    const findings = [match(1, false), match(2, true), match(3, false), match(4, true)];
    assert.deepEqual(splitSuppressed(findings), { open: [0, 2], suppressed: [1, 3] });
  });

  it("treats findings saved before suppressions as open", () => {
    const { suppression: _, ...older } = match(1, false);
    assert.deepEqual(splitSuppressed([older]), { open: [0], suppressed: [] });
  });
});

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
