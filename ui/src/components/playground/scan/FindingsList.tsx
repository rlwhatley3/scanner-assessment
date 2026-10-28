import { useMemo, useState } from "react";
import type { MatchFinding } from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS, SEVERITY_ORDER, SeverityIcon } from "../severity.tsx";

interface FindingsListProps {
  findings: MatchFinding[];
  selected: number[];
  onSelect: (index: number) => void;
}

export function findingElementId(index: number): string {
  return `scan-finding-${index}`;
}

function formatLocation({ location }: MatchFinding["violation"]): string {
  const start = `${location.start_line}:${location.start_column}`;
  return location.end_line === location.start_line
    ? `Line ${start}–${location.end_column}`
    : `Lines ${start} – ${location.end_line}:${location.end_column}`;
}

/** Matches in text order by default, or by severity. Clicking one selects its highlight. */
export default function FindingsList({ findings, selected, onSelect }: FindingsListProps) {
  const [sortBySeverity, setSortBySeverity] = useState(false);

  const order = useMemo(() => {
    const indices = findings.map((_, index) => index);
    if (!sortBySeverity) return indices;
    return indices.sort(
      (a, b) =>
        SEVERITY_ORDER[findings[a].violation.severity] -
          SEVERITY_ORDER[findings[b].violation.severity] || a - b,
    );
  }, [findings, sortBySeverity]);

  return (
    <section className="findings" aria-label="Findings">
      <header className="findings-header">
        <h2>
          {findings.length} {findings.length === 1 ? "finding" : "findings"}
        </h2>
        <label className="findings-sort">
          <input
            type="checkbox"
            checked={sortBySeverity}
            onChange={(event) => setSortBySeverity(event.target.checked)}
          />
          Sort by severity
        </label>
      </header>
      <ol className="findings-list">
        {order.map((index) => {
          const details = findings[index].violation;
          return (
            <li key={index} id={findingElementId(index)}>
              <button
                type="button"
                className={`finding tone-${details.severity}${
                  selected.includes(index) ? " selected" : ""
                }`}
                aria-pressed={selected.includes(index)}
                onClick={() => onSelect(index)}
              >
                <span className="finding-title">
                  <SeverityIcon tone={details.severity} />
                  <strong>{details.rule_name}</strong>
                  <span className="finding-location">{formatLocation(details)}</span>
                </span>
                <span className="finding-meta">
                  {SEVERITY_LABELS[details.severity]} · {DETECTION_LABELS[details.detection_type]} ·
                  Confidence {details.confidence}
                  {details.placeholder_score !== null &&
                    ` · Placeholder ${details.placeholder_score}`}
                  {details.redacted_preview && (
                    <>
                      {" "}
                      · <code>{details.redacted_preview}</code>
                    </>
                  )}
                </span>
                {selected.includes(index) && (
                  <span className="finding-details">
                    <span>
                      <b>Why flagged:</b> {details.why_flagged}
                    </span>
                    <span>
                      <b>Fix:</b> {details.remediation}
                    </span>
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
