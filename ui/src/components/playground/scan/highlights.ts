import type { FindingSuppression, MatchFinding, Severity } from "../api.ts";

/** One highlighted range of the scan text, covering one finding or an overlapping set. */
export interface Highlight {
  /** UTF-16 indices into the text, ready for `String.prototype.slice`. */
  start: number;
  end: number;
  /** Indices into the findings array passed to `buildHighlights`. */
  findings: number[];
  /** A single finding's severity, "overlap" when several findings share the range, or
   * "suppressed" when a suppression covers every finding in it. */
  tone: HighlightTone;
}

export type HighlightTone = Severity | "overlap" | "suppressed";

/** A match, with the suppression that covered it when it has one. */
type HighlightedFinding = MatchFinding & { suppression?: FindingSuppression | null };

export type Segment = { text: string; highlight: Highlight | null };

/**
 * Maps UTF-8 byte offsets (what the engine reports) to UTF-16 indices (what JS strings use).
 * An offset that falls inside a character maps to the end of that character.
 */
export function byteOffsetsToIndices(text: string, byteOffsets: number[]): Map<number, number> {
  const wanted = [...new Set(byteOffsets)].sort((a, b) => a - b);
  const indices = new Map<number, number>();
  let next = 0;
  let bytes = 0;
  let index = 0;
  while (next < wanted.length && index < text.length) {
    while (next < wanted.length && wanted[next] <= bytes) {
      indices.set(wanted[next], index);
      next += 1;
    }
    const codePoint = text.codePointAt(index) ?? 0;
    bytes += codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4;
    index += codePoint > 0xffff ? 2 : 1;
  }
  for (; next < wanted.length; next += 1) indices.set(wanted[next], text.length);
  return indices;
}

/**
 * Turns match findings into non-overlapping highlights. Findings that share an engine overlap
 * group become one highlight; any ranges that still overlap are merged as a safety net.
 */
export function buildHighlights(text: string, findings: HighlightedFinding[]): Highlight[] {
  const indices = byteOffsetsToIndices(
    text,
    findings.flatMap((finding) => [
      finding.violation.location.startByte,
      finding.violation.location.endByte,
    ]),
  );

  const byGroup = new Map<string, Highlight>();
  findings.forEach((finding, position) => {
    const { location, overlapGroup } = finding.violation;
    const start = indices.get(location.startByte) ?? 0;
    const end = indices.get(location.endByte) ?? start;
    const key = overlapGroup === null ? `finding-${position}` : `group-${overlapGroup}`;
    const existing = byGroup.get(key);
    if (existing) {
      existing.start = Math.min(existing.start, start);
      existing.end = Math.max(existing.end, end);
      existing.findings.push(position);
    } else {
      byGroup.set(key, { start, end, findings: [position], tone: finding.violation.severity });
    }
  });

  const sorted = [...byGroup.values()]
    .filter((highlight) => highlight.end > highlight.start)
    .sort((a, b) => a.start - b.start || b.end - a.end);

  const merged: Highlight[] = [];
  for (const highlight of sorted) {
    const previous = merged.at(-1);
    if (previous && highlight.start < previous.end) {
      previous.end = Math.max(previous.end, highlight.end);
      previous.findings.push(...highlight.findings);
    } else {
      merged.push({ ...highlight, findings: [...highlight.findings] });
    }
  }
  for (const highlight of merged) {
    highlight.findings.sort((a, b) => a - b);
    if (highlight.findings.every((index) => findings[index].suppression)) {
      highlight.tone = "suppressed";
    } else if (highlight.findings.length > 1) {
      highlight.tone = "overlap";
    }
  }
  return merged;
}

/** Splits the text into plain and highlighted runs, in order. */
export function segmentText(text: string, highlights: Highlight[]): Segment[] {
  const segments: Segment[] = [];
  let cursor = 0;
  for (const highlight of highlights) {
    if (highlight.start > cursor) {
      segments.push({ text: text.slice(cursor, highlight.start), highlight: null });
    }
    segments.push({ text: text.slice(highlight.start, highlight.end), highlight });
    cursor = highlight.end;
  }
  if (cursor < text.length) segments.push({ text: text.slice(cursor), highlight: null });
  return segments;
}
