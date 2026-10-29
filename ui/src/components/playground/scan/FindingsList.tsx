import { useMemo, useState } from "react";
import { formatDate, type SavedMatch, type Suppression } from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS, SEVERITY_ORDER, SeverityIcon } from "../severity.tsx";
import SuppressForm from "./SuppressForm.tsx";

interface FindingsListProps {
  findings: SavedMatch[];
  selected: number[];
  onSelect: (index: number) => void;
  /** The session's suppressions, to show which of these findings one was made from. */
  suppressions?: Suppression[];
  /** Suppresses a finding's value in the session. Without it, findings can't be suppressed. */
  onSuppress?: (finding: SavedMatch, reason: string, expiresAt: string) => Promise<void>;
}

const VALUE_LABELS = {
  credential: "credential",
  non_secret: "non-secret",
  placeholder: "placeholder",
};

export function findingElementId(index: number): string {
  return `scan-finding-${index}`;
}

function formatLocation({ location }: SavedMatch["violation"]): string {
  const start = `${location.startLine}:${location.startColumn}`;
  return location.endLine === location.startLine
    ? `Line ${start}–${location.endColumn}`
    : `Lines ${start} – ${location.endLine}:${location.endColumn}`;
}

/** Matches in text order by default, or by severity. Clicking one selects its highlight, and a
 * selected one can be suppressed. */
export default function FindingsList({
  findings,
  selected,
  onSelect,
  suppressions = [],
  onSuppress,
}: FindingsListProps) {
  const [sortBySeverity, setSortBySeverity] = useState(false);
  const [suppressing, setSuppressing] = useState<number | null>(null);
  const activeByFinding = useMemo(
    () =>
      new Map(
        suppressions
          .filter((suppression) => suppression.status === "active")
          .map((suppression) => [suppression.findingId, suppression]),
      ),
    [suppressions],
  );

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
          const finding = findings[index];
          const details = finding.violation;
          const suppression = activeByFinding.get(finding.id);
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
                {suppression && (
                  <span className="finding-suppression">
                    <b>Suppressed</b> until {formatDate(suppression.expiresAt)}: later scans in this
                    session won't flag this value. {suppression.reason}
                  </span>
                )}
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
              {selected.includes(index) &&
                !suppression &&
                onSuppress &&
                (suppressing === finding.id ? (
                  <SuppressForm
                    onSubmit={async (reason, expiresAt) => {
                      await onSuppress(finding, reason, expiresAt);
                      setSuppressing(null);
                    }}
                    onCancel={() => setSuppressing(null)}
                  />
                ) : (
                  <div className="finding-actions">
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => setSuppressing(finding.id)}
                    >
                      Suppress this value…
                    </button>
                  </div>
                ))}
            </li>
          );
        })}
      </ol>
    </section>
  );
}
