import { useMemo, useState } from "react";
import type { MatchFinding } from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS, SEVERITY_ORDER, SeverityIcon } from "../severity.tsx";

interface FindingsListProps {
  findings: MatchFinding[];
  selected: number[];
  onSelect: (index: number) => void;
}

const VALUE_LABELS = {
  credential: "credential",
  non_secret: "non-secret",
  placeholder: "placeholder",
};

export function findingElementId(index: number): string {
  return `scan-finding-${index}`;
}

function formatLocation({ location }: MatchFinding["violation"]): string {
  const start = `${location.startLine}:${location.startColumn}`;
  return location.endLine === location.startLine
    ? `Line ${start}–${location.endColumn}`
    : `Lines ${start} – ${location.endLine}:${location.endColumn}`;
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
                  <strong>{details.ruleName}</strong>
                  <span className="finding-location">{formatLocation(details)}</span>
                </span>
                <span className="finding-meta">
                  {SEVERITY_LABELS[details.severity]} · {DETECTION_LABELS[details.detectionType]} ·
                  Confidence {details.confidence}
                  {details.placeholderScore !== null &&
                    ` · Placeholder ${details.placeholderScore}`}
                  {details.checksumValid !== null &&
                    (details.checksumValid ? " · Checksum valid" : " · Checksum fails")}
                  {details.inComment && " · In a comment"}
                  {details.valueClass && (
                    <span className={`value-class ${details.valueClass.label}`}>
                      {" "}
                      · Value: {VALUE_LABELS[details.valueClass.label]} (
                      {details.valueClass.label === "credential"
                        ? details.valueClass.credential
                        : details.valueClass.label === "non_secret"
                          ? details.valueClass.nonSecret
                          : details.valueClass.placeholder}
                      )
                    </span>
                  )}
                  {details.modelAssessments?.map((assessment) => (
                    <span key={assessment.ruleId} className={`model-verdict ${assessment.verdict}`}>
                      {" "}
                      · {assessment.ruleName}:{" "}
                      {assessment.verdict === "likely_real" ? "likely real" : "likely an example"} (
                      {assessment.score})
                    </span>
                  ))}
                  {details.redactedPreview && (
                    <>
                      {" "}
                      · <code>{details.redactedPreview}</code>
                    </>
                  )}
                </span>
                {selected.includes(index) && (
                  <span className="finding-details">
                    <span>
                      <b>Why flagged:</b> {details.whyFlagged}
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
