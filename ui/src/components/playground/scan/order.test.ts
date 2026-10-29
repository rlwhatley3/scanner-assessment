import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { MatchDetails } from "../api.ts";
import { likelyRealOrder, looksLikeExample } from "./order.ts";

function details(confidence: number, overrides: Partial<MatchDetails> = {}): MatchDetails {
  return {
    ruleName: "Test rule",
    detectionType: "direct_credential",
    severity: "high",
    confidence,
    placeholderScore: 0,
    location: {
      startByte: 0,
      endByte: 1,
      startLine: 1,
      startColumn: 1,
      endLine: 1,
      endColumn: 1,
    },
    redactedPreview: null,
    whyFlagged: "",
    remediation: "",
    overlapGroup: null,
    inComment: false,
    checksumValid: null,
    ...overrides,
  };
}

function order(...violations: MatchDetails[]): number[] {
  return likelyRealOrder(violations.map((violation) => ({ violation })));
}

describe("looksLikeExample", () => {
  it("is false for a plain match", () => {
    assert.equal(looksLikeExample(details(90)), false);
    assert.equal(looksLikeExample(details(90, { placeholderScore: null })), false);
  });

  it("is true for a high placeholder score", () => {
    assert.equal(looksLikeExample(details(90, { placeholderScore: 49 })), false);
    assert.equal(looksLikeExample(details(90, { placeholderScore: 50 })), true);
  });

  it("is true when a value classifier calls it a placeholder", () => {
    const valueClass = { credential: 10, nonSecret: 10, placeholder: 80 };
    assert.equal(
      looksLikeExample(details(90, { valueClass: { label: "placeholder", ...valueClass } })),
      true,
    );
    assert.equal(
      looksLikeExample(details(90, { valueClass: { label: "non_secret", ...valueClass } })),
      false,
    );
  });

  it("is true when any model calls it an example", () => {
    const assessment = { ruleId: 1, ruleName: "Model", score: 50 };
    assert.equal(
      looksLikeExample(
        details(90, {
          modelAssessments: [
            { ...assessment, verdict: "likely_real" },
            { ...assessment, ruleId: 2, verdict: "likely_example" },
          ],
        }),
      ),
      true,
    );
    assert.equal(
      looksLikeExample(
        details(90, { modelAssessments: [{ ...assessment, verdict: "likely_real" }] }),
      ),
      false,
    );
  });
});

describe("likelyRealOrder", () => {
  it("puts higher confidence first", () => {
    assert.deepEqual(order(details(40), details(90), details(60)), [1, 2, 0]);
  });

  it("puts examples after everything else, whatever their confidence", () => {
    assert.deepEqual(
      order(details(99, { placeholderScore: 80 }), details(30), details(70)),
      [2, 1, 0],
    );
  });

  it("orders examples by confidence among themselves", () => {
    assert.deepEqual(
      order(details(40, { placeholderScore: 80 }), details(90, { placeholderScore: 80 })),
      [1, 0],
    );
  });

  it("keeps text order for ties", () => {
    assert.deepEqual(order(details(70), details(70), details(90), details(70)), [2, 0, 1, 3]);
  });

  it("handles no findings", () => {
    assert.deepEqual(order(), []);
  });
});
