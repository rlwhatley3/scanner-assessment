import { useMemo } from "react";
import { SeverityIcon } from "../severity.tsx";
import { type Highlight, segmentText } from "./highlights.ts";

interface ScanTextProps {
  text: string;
  highlights: Highlight[];
  selected: Highlight | null;
  onSelect: (highlight: Highlight) => void;
}

export function highlightElementId(highlight: Highlight): string {
  return `scan-highlight-${highlight.start}`;
}

/** The scanned text, read-only, with each finding (or overlapping set) highlighted. */
export default function ScanText({ text, highlights, selected, onSelect }: ScanTextProps) {
  const segments = useMemo(() => segmentText(text, highlights), [text, highlights]);

  return (
    <pre className="scan-text">
      {segments.map((segment) =>
        segment.highlight ? (
          <mark
            key={segment.highlight.start}
            id={highlightElementId(segment.highlight)}
            className={`scan-highlight tone-${segment.highlight.tone}${
              segment.highlight === selected ? " selected" : ""
            }`}
          >
            <button
              type="button"
              className="scan-highlight-target"
              onClick={() => onSelect(segment.highlight as Highlight)}
              aria-label={
                segment.highlight.findings.length > 1
                  ? `${segment.highlight.findings.length} overlapping findings`
                  : "Finding"
              }
            >
              <SeverityIcon tone={segment.highlight.tone} />
            </button>
            {segment.text}
          </mark>
        ) : (
          segment.text
        ),
      )}
    </pre>
  );
}
