import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { MatchFinding, Severity } from "./api.ts";
import { buildHighlights, byteOffsetsToIndices, segmentText } from "./highlights.ts";

function match(
  startByte: number,
  endByte: number,
  severity: Severity = "high",
  overlapGroup: number | null = null,
): MatchFinding {
  return {
    rule_id: 1,
    kind: "match",
    violation_pretty: "",
    violation: {
      rule_name: "Test rule",
      detection_type: "direct_credential",
      severity,
      confidence: 90,
      placeholder_score: 0,
      location: {
        start_byte: startByte,
        end_byte: endByte,
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 1,
      },
      redacted_preview: null,
      why_flagged: "",
      remediation: "",
      overlap_group: overlapGroup,
    },
  };
}

describe("byteOffsetsToIndices", () => {
  it("is the identity for ASCII", () => {
    const indices = byteOffsetsToIndices("abcdef", [0, 3, 6]);
    assert.deepEqual(
      [...indices],
      [
        [0, 0],
        [3, 3],
        [6, 6],
      ],
    );
  });

  it("accounts for multi-byte characters before the offset", () => {
    // "é" is 2 bytes, "€" is 3, "😀" is 4 bytes and 2 UTF-16 units.
    const text = "é€😀x";
    const indices = byteOffsetsToIndices(text, [2, 5, 9, 10]);
    assert.equal(indices.get(2), 1);
    assert.equal(indices.get(5), 2);
    assert.equal(indices.get(9), 4);
    assert.equal(indices.get(10), 5);
    assert.equal(text.slice(indices.get(9), indices.get(10)), "x");
  });

  it("clamps offsets past the end to the text length", () => {
    assert.equal(byteOffsetsToIndices("ab", [99]).get(99), 2);
  });
});

describe("buildHighlights", () => {
  it("keeps separate findings separate, in text order", () => {
    const highlights = buildHighlights("aaaa bbbb", [match(5, 9, "low"), match(0, 4)]);
    assert.deepEqual(
      highlights.map(({ start, end, findings, tone }) => ({ start, end, findings, tone })),
      [
        { start: 0, end: 4, findings: [1], tone: "high" },
        { start: 5, end: 9, findings: [0], tone: "low" },
      ],
    );
  });

  it("draws an engine overlap group as one purple highlight", () => {
    const highlights = buildHighlights("token=abcdef", [
      match(0, 12, "low", 7),
      match(6, 12, "high", 7),
    ]);
    assert.equal(highlights.length, 1);
    assert.deepEqual(highlights[0], { start: 0, end: 12, findings: [0, 1], tone: "overlap" });
  });

  it("merges ranges that overlap without a shared group", () => {
    const highlights = buildHighlights("abcdefgh", [match(0, 5), match(3, 8, "medium")]);
    assert.equal(highlights.length, 1);
    assert.equal(highlights[0].tone, "overlap");
    assert.equal(highlights[0].end, 8);
  });

  it("skips empty ranges", () => {
    assert.deepEqual(buildHighlights("abc", [match(1, 1)]), []);
  });
});

describe("segmentText", () => {
  it("covers the whole text exactly once", () => {
    const text = "key=é😀secret end";
    const highlights = buildHighlights(text, [match(4, 13)]);
    const segments = segmentText(text, highlights);
    assert.equal(segments.map((segment) => segment.text).join(""), text);
    assert.equal(segments[1].text, "é😀sec");
  });
});
