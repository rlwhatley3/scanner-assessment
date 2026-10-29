import { useEffect, useMemo, useState } from "react";
import { formatDate, type SavedMatch } from "../api.ts";
import { DETECTION_LABELS, SEVERITY_LABELS, SEVERITY_ORDER, SeverityIcon } from "../severity.tsx";
import SuppressForm from "./SuppressForm.tsx";
import { splitSuppressed } from "./suppressions.ts";

interface FindingsListProps {
  findings: SavedMatch[];
  selected: number[];
  onSelect: (index: number) => void;
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

/**
 * Matches in text order by default, or by severity. Clicking one selects its highlight. Matches
 * a suppression covers are still listed and counted, collapsed under their own heading.
 */
export default function FindingsList({
  findings,
  selected,
  onSelect,
  onSuppress,
}: FindingsListProps) {
  const [sortBySeverity, setSortBySeverity] = useState(false);
  const [showSuppressed, setShowSuppressed] = useState(false);

  const { open, suppressed } = useMemo(() => {
    const groups = splitSuppressed(findings);
    if (sortBySeverity) {
      const bySeverity = (a: number, b: number) =>
        SEVERITY_ORDER[findings[a].violation.severity] -
          SEVERITY_ORDER[findings[b].violation.severity] || a - b;
      groups.open.sort(bySeverity);
      groups.suppressed.sort(bySeverity);
    }
    return groups;
  }, [findings, sortBySeverity]);

  // Selecting a suppressed finding from its highlight opens the group so it can be seen.
  useEffect(() => {
    if (selected.some((index) => findings[index]?.suppression)) setShowSuppressed(true);
  }, [selected, findings]);

  const renderFinding = (index: number) => (
    <FindingItem
      key={index}
      index={index}
      finding={findings[index]}
      selected={selected.includes(index)}
      onSelect={onSelect}
      onSuppress={onSuppress}
    />
  );

  return (
    <section className="findings" aria-label="Findings">
      <header className="findings-header">
        <h2>
          {findings.length} {findings.length === 1 ? "finding" : "findings"}
          {suppressed.length > 0 && (
            <span className="muted small"> · {suppressed.length} suppressed</span>
          )}
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
      {open.length > 0 ? (
        <ol className="findings-list">{open.map(renderFinding)}</ol>
      ) : (
        <p className="muted small">Every finding is suppressed.</p>
      )}
      {suppressed.length > 0 && (
        <details
          className="suppressed-group"
          open={showSuppressed}
          onToggle={(event) => setShowSuppressed(event.currentTarget.open)}
        >
          <summary>Suppressed ({suppressed.length})</summary>
          <p className="muted small suppress-note">
            Marked safe in this session. They stay in the results and the count, and come back when
            the value changes or the suppression expires.
          </p>
          <ol className="findings-list">{suppressed.map(renderFinding)}</ol>
        </details>
      )}
    </section>
  );
}

interface FindingItemProps {
  index: number;
  finding: SavedMatch;
  selected: boolean;
  onSelect: (index: number) => void;
  onSuppress?: (finding: SavedMatch, reason: string, expiresAt: string) => Promise<void>;
}

function FindingItem({ index, finding, selected, onSelect, onSuppress }: FindingItemProps) {
  const [suppressing, setSuppressing] = useState(false);
  const details = finding.violation;
  const { suppression } = finding;

  return (
    <li id={findingElementId(index)}>
      <button
        type="button"
        className={`finding tone-${suppression ? "suppressed" : details.severity}${
          selected ? " selected" : ""
        }`}
        aria-pressed={selected}
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
        {suppression && (
          <span className="finding-suppression">
            <b>Suppressed:</b> {suppression.reason} · until {formatDate(suppression.expiresAt)} ·
            suppression {suppression.id}
          </span>
        )}
        {selected && (
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
      {selected &&
        !suppression &&
        onSuppress &&
        (suppressing ? (
          <SuppressForm
            onSubmit={(reason, expiresAt) => onSuppress(finding, reason, expiresAt)}
            onCancel={() => setSuppressing(false)}
          />
        ) : (
          <div className="finding-actions">
            <button type="button" className="link-button" onClick={() => setSuppressing(true)}>
              Suppress this value…
            </button>
          </div>
        ))}
    </li>
  );
}
