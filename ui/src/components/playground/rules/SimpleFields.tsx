import { useId } from "react";
import type { DetectionType, Severity } from "../api.ts";
import { SeverityIcon } from "../severity.tsx";
import { CHARSETS, type Charset, NEW_PREFIX_SHAPE, type Shape } from "./shape.ts";

// Plain-language pieces of the simple rule editor. The advanced form edits the same fields.

/** What a rule that the simple editor can't describe does, in plain words. */
function describeCustom(detectionType: DetectionType | "", pattern: string): React.ReactNode {
  switch (detectionType) {
    case "unsafe_handling":
      return "Flags code that may print or log a secret.";
    case "placeholder_vs_real":
      return "Lists example values, like “changeme”, so findings that use them are rated as likely examples. It finds nothing on its own.";
    case "model_assessment":
      return "Uses a trained model to rate whether other rules' findings look real. It finds nothing on its own.";
    case "model_detection":
      return "Uses a trained model to spot secrets.";
    default:
      return (
        <>
          Finds text matching a custom pattern: <code className="pattern">{pattern}</code>
        </>
      );
  }
}

interface SecretShapeProps {
  shape: Shape;
  onChange: (shape: Shape) => void;
  detectionType: DetectionType | "";
  pattern: string;
  /** Turns on the advanced settings, to edit a custom rule. */
  onAdvanced: () => void;
}

/** "What does the secret look like?" as a choice between shapes the editor writes a pattern for. */
export function SecretShape({
  shape,
  onChange,
  detectionType,
  pattern,
  onAdvanced,
}: SecretShapeProps) {
  const id = useId();
  const custom = shape.kind === "custom";

  return (
    <fieldset className="simple-question">
      <legend>What does the secret look like?</legend>
      {custom ? (
        <div className="simple-custom">
          <p>{describeCustom(detectionType, pattern)}</p>
          <p className="muted small">
            This rule was written by hand.{" "}
            <button type="button" className="link-button" onClick={onAdvanced}>
              Turn on advanced settings
            </button>{" "}
            to change how it finds things, or{" "}
            <button
              type="button"
              className="link-button"
              onClick={() => onChange(NEW_PREFIX_SHAPE)}
            >
              describe it again from scratch
            </button>
            .
          </p>
        </div>
      ) : (
        <>
          <label className="simple-option">
            <input
              type="radio"
              name={`${id}-shape`}
              checked={shape.kind === "prefix"}
              onChange={() => onChange(NEW_PREFIX_SHAPE)}
            />
            <span>
              <b>It always starts with the same text</b>
              <span className="muted small">e.g. company tokens like acme_8f2k…</span>
            </span>
          </label>
          {shape.kind === "prefix" && (
            <div className="simple-sentence">
              Starts with{" "}
              <input
                className="mono"
                aria-label="Starting text"
                placeholder="acme_"
                size={10}
                value={shape.prefix}
                onChange={(event) => onChange({ ...shape, prefix: event.target.value })}
              />
              , then{" "}
              <input
                type="number"
                aria-label="Number of characters after it"
                min={1}
                max={500}
                className="simple-length"
                value={shape.length}
                onChange={(event) => onChange({ ...shape, length: event.target.value })}
              />{" "}
              <select
                aria-label="Kind of characters"
                value={shape.charset}
                onChange={(event) => onChange({ ...shape, charset: event.target.value as Charset })}
              >
                {Object.entries(CHARSETS).map(([key, { label }]) => (
                  <option key={key} value={key}>
                    {label}
                  </option>
                ))}
              </select>
              .
            </div>
          )}

          <label className="simple-option">
            <input
              type="radio"
              name={`${id}-shape`}
              checked={shape.kind === "label"}
              onChange={() => onChange({ kind: "label", labels: "password, token, secret" })}
            />
            <span>
              <b>It comes after a label</b>
              <span className="muted small">e.g. password = hunter2, or token: 8f2k…</span>
            </span>
          </label>
          {shape.kind === "label" && (
            <div className="simple-sentence">
              After a label like{" "}
              <input
                aria-label="Labels, separated by commas"
                placeholder="password, token"
                size={28}
                value={shape.labels}
                onChange={(event) => onChange({ kind: "label", labels: event.target.value })}
              />
              <span className="muted small"> Separate labels with commas.</span>
            </div>
          )}

          <p className="muted small">
            Something else?{" "}
            <button type="button" className="link-button" onClick={onAdvanced}>
              Write a custom pattern in advanced settings
            </button>
            .
          </p>
        </>
      )}
    </fieldset>
  );
}

const SEVERITY_MEANINGS: Record<Severity, string> = {
  high: "A real key or password. Fix it right away.",
  medium: "Probably a secret. Check it soon.",
  low: "Worth a look, but often harmless.",
};

/** "How serious is it?" as three plain choices. */
export function SeverityChoice({
  value,
  onChange,
}: {
  value: Severity | "";
  onChange: (severity: Severity) => void;
}) {
  const id = useId();
  return (
    <fieldset className="simple-question">
      <legend>How serious is it if one is found?</legend>
      <div className="severity-choices">
        {(Object.keys(SEVERITY_MEANINGS) as Severity[]).map((severity) => (
          <label
            key={severity}
            className={`severity-choice${value === severity ? " selected" : ""}`}
          >
            <input
              type="radio"
              name={`${id}-severity`}
              checked={value === severity}
              onChange={() => onChange(severity)}
            />
            <span>
              <b>
                <SeverityIcon tone={severity} /> {severity[0].toUpperCase() + severity.slice(1)}
              </b>
              <span className="muted small">{SEVERITY_MEANINGS[severity]}</span>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
