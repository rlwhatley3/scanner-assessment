import { useEffect, useMemo, useState } from "react";
import { type RuleDefinition, type SavedMatch, type TryRuleResponse, tryRule } from "../api.ts";
import FindingsList from "../scan/FindingsList.tsx";
import { buildHighlights, type Highlight } from "../scan/highlights.ts";
import ScanText from "../scan/ScanText.tsx";

const TRY_DELAY_MS = 500;

interface TryRuleProps {
  ruleId: number;
  /** The definition as it stands in the form, saved or not. */
  definition: RuleDefinition;
}

/** Runs the rule being edited on sample text, without saving anything. Once tried, it runs
 * again as the rule or the text changes. The text lives only in this component's state. */
export default function TryRule({ ruleId, definition }: TryRuleProps) {
  const [text, setText] = useState("");
  const [live, setLive] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<TryRuleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [showText, setShowText] = useState(false);
  const isBlank = text.trim() === "";

  useEffect(() => {
    if (!live || isBlank) return;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      setRunning(true);
      tryRule(ruleId, definition, text, controller.signal).then(
        (response) => {
          setResult(response);
          setError(null);
          setSelected([]);
          setRunning(false);
        },
        (reason: unknown) => {
          if (controller.signal.aborted) return;
          setResult(null);
          setError(reason instanceof Error ? reason.message : "Could not try the rule.");
          setRunning(false);
        },
      );
    }, TRY_DELAY_MS);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [live, isBlank, ruleId, definition, text]);

  // Ids are only for the list's keys; nothing here is saved.
  const matches = useMemo(
    () =>
      (result?.findings ?? [])
        .filter((finding) => finding.kind === "match")
        .map((finding, index) => ({ ...finding, id: index }) as SavedMatch),
    [result],
  );
  const ruleErrors = (result?.findings ?? []).filter((finding) => finding.kind === "rule_error");
  const highlights = useMemo(() => buildHighlights(text, matches), [text, matches]);
  const selectedHighlight =
    highlights.find((highlight) => selected.some((index) => highlight.findings.includes(index))) ??
    null;

  return (
    <section className="try-rule" aria-label="Check it with an example">
      <h3>Check it with an example</h3>
      <p className="muted small">
        Paste a line or two with the kind of secret this rule should catch, to see what it finds.
        Works before you save, and nothing you paste here is kept.
      </p>
      <textarea
        className="mono"
        rows={4}
        spellCheck={false}
        autoComplete="off"
        aria-label="Sample text for this rule"
        placeholder="e.g. aws_access_key_id = AKIA…"
        value={text}
        onChange={(event) => setText(event.target.value)}
      />
      <div className="form-actions">
        {!live ? (
          <button type="button" className="button" onClick={() => setLive(true)} disabled={isBlank}>
            Check
          </button>
        ) : (
          <span className="muted small" role="status">
            {running ? "Checking…" : "Checks again as you change the rule or the example."}
          </span>
        )}
        {result && matches.length > 0 && (
          <button type="button" className="link-button" onClick={() => setShowText((on) => !on)}>
            {showText ? "Hide highlights" : "Show highlights"}
          </button>
        )}
      </div>
      {error && (
        <p className="banner error" role="alert">
          {error}
        </p>
      )}
      {ruleErrors.map((finding) => (
        <p key={finding.violationPretty} className="banner warning" role="alert">
          The rule isn't finished yet: {finding.violationPretty}
        </p>
      ))}
      {result && ruleErrors.length === 0 && matches.length === 0 && (
        <p className="banner info" role="status">
          This rule finds nothing in the example.
        </p>
      )}
      {showText && matches.length > 0 && (
        <ScanText
          text={text}
          highlights={highlights}
          selected={selectedHighlight}
          onSelect={(highlight: Highlight) => setSelected(highlight.findings)}
        />
      )}
      {matches.length > 0 && (
        <FindingsList
          findings={matches}
          selected={selected}
          onSelect={(index) => setSelected([index])}
        />
      )}
    </section>
  );
}
