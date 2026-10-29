import { useMemo, useState } from "react";
import { formatDate, type SavedMatch, type Severity, type Suppression } from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS, SEVERITY_ORDER, SeverityIcon } from "../severity.tsx";
import { likelyRealOrder, looksLikeExample } from "./order.ts";
import SuppressForm from "./SuppressForm.tsx";

interface FindingsListProps {
  findings: SavedMatch[];
  selected: number[];
  onSelect: (index: number) => void;
  /** The session's suppressions, to show which of these findings one was made from. */
  suppressions?: Suppression[];
  /** Marks a finding's value as safe in the session. Without it, findings can't be marked. */
  onSuppress?: (finding: SavedMatch, reason: string, expiresAt: string) => Promise<void>;
}

type SortOrder = "text" | "severity" | "likely_real";

const SORT_LABELS: Record<SortOrder, string> = {
  text: "Text order",
  severity: "Severity",
  likely_real: "Likely real first",
};

const VALUE_LABELS = {
  credential: "credential",
  non_secret: "non-secret",
  placeholder: "placeholder",
};

export function findingElementId(index: number): string {
  return `scan-finding-${index}`;
}

function formatLocation({ location }: SavedMatch["violation"]): string {
  return location.endLine === location.startLine
    ? `Line ${location.startLine}`
    : `Lines ${location.startLine}–${location.endLine}`;
}

/** How likely the match is a real secret, in plain words, from its scores and any model's or
 * value classifier's verdict. */
export function likelihood(details: SavedMatch["violation"]): string {
  if (looksLikeExample(details)) return "Looks like an example value";
  if (details.valueClass?.label === "non_secret") return "Might not be a secret";
  if (details.confidence >= 80) return "Very likely real";
  if (details.confidence >= 50) return "Probably real";
  return "Might be real";
}

/** Matches in text order by default, or by severity or how likely each is real. Clicking one selects its highlight, and a
 * selected one can be marked as safe. */
export default function FindingsList({
  findings,
  selected,
  onSelect,
  suppressions = [],
  onSuppress,
}: FindingsListProps) {
  const [sortOrder, setSortOrder] = useState<SortOrder>("text");
  const [suppressing, setSuppressing] = useState<number | null>(null);
  const [technical, setTechnical] = useState<number | null>(null);
  const activeByFinding = useMemo(
    () =>
      new Map(
        suppressions
          .filter((suppression) => suppression.status === "active")
          .map((suppression) => [suppression.findingId, suppression]),
      ),
    [suppressions],
  );

  // e.g. "2 high, 1 medium", most severe first.
  const bySeverity = useMemo(() => {
    const counts = new Map<Severity, number>();
    for (const finding of findings) {
      const { severity } = finding.violation;
      counts.set(severity, (counts.get(severity) ?? 0) + 1);
    }
    return [...counts]
      .sort(([a], [b]) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])
      .map(([severity, count]) => `${count} ${SEVERITY_LABELS[severity].toLowerCase()}`)
      .join(", ");
  }, [findings]);

  const order = useMemo(() => {
    if (sortOrder === "likely_real") return likelyRealOrder(findings);
    const indices = findings.map((_, index) => index);
    if (sortOrder === "text") return indices;
    return indices.sort(
      (a, b) =>
        SEVERITY_ORDER[findings[a].violation.severity] -
          SEVERITY_ORDER[findings[b].violation.severity] || a - b,
    );
  }, [findings, sortOrder]);

  return (
    <section className="findings" aria-label="Findings">
      <header className="findings-header">
        <h2>
          {findings.length} {findings.length === 1 ? "finding" : "findings"}
          {bySeverity && <span className="findings-breakdown">: {bySeverity}</span>}
        </h2>
        <label className="findings-sort">
          Sort by
          <select
            value={sortOrder}
            onChange={(event) => setSortOrder(event.target.value as SortOrder)}
          >
            {Object.entries(SORT_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
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
                  {SEVERITY_LABELS[details.severity]} · {likelihood(details)}
                  {details.inComment && " · In a comment"}
                  {details.redactedPreview && (
                    <>
                      {" "}
                      · starts with <code>{details.redactedPreview}</code>
                    </>
                  )}
                </span>
                {suppression && (
                  <span className="finding-suppression">
                    <b>Marked safe</b> until {formatDate(suppression.expiresAt)}: later scans in
                    this session won't flag this value. {suppression.reason}
                  </span>
                )}
                {selected.includes(index) && (
                  <span className="finding-details">
                    <span>
                      <b>Why it was flagged:</b> {details.whyFlagged}
                    </span>
                    <span>
                      <b>How to fix it:</b> {details.remediation}
                    </span>
                  </span>
                )}
              </button>
              {selected.includes(index) && (
                <div className="finding-actions">
                  <button
                    type="button"
                    className="link-button"
                    aria-expanded={technical === finding.id}
                    onClick={() => setTechnical(technical === finding.id ? null : finding.id)}
                  >
                    {technical === finding.id ? "Hide technical details" : "Technical details"}
                  </button>
                  {technical === finding.id && <TechnicalDetails details={details} />}
                </div>
              )}
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
                      Mark as safe…
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

/** The engine's own terms and scores, for people who want them. */
function TechnicalDetails({ details }: { details: SavedMatch["violation"] }) {
  const { location } = details;
  return (
    <span className="finding-technical">
      {location.startLine}:{location.startColumn}–{location.endLine}:{location.endColumn} ·{" "}
      {DETECTION_LABELS[details.detectionType]} · Confidence {details.confidence}
      {details.placeholderScore !== null && ` · Placeholder ${details.placeholderScore}`}
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
  );
}
