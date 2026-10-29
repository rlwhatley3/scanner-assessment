import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  createSession,
  createSuppression,
  formatDate,
  getVersion,
  listSuppressions,
  MAX_FINDINGS,
  MAX_INPUT_BYTES,
  runScan,
  type SavedMatch,
  type ScanResponse,
} from "../api.ts";
import { useActiveSession } from "../session.tsx";
import { useLoad } from "../useLoad.ts";
import FindingsList, { findingElementId } from "./FindingsList.tsx";
import { buildHighlights, type Highlight } from "./highlights.ts";
import ScanText, { highlightElementId } from "./ScanText.tsx";
import SessionBar from "./SessionBar.tsx";
import SuppressionsPanel from "./SuppressionsPanel.tsx";
import { SAMPLES } from "./samples.ts";

// The scan text lives only in component state: never in storage, the URL, or a log.
// The view stays mounted while the user visits other menu sections, so the text survives.
type Phase = { kind: "editing" } | { kind: "scanning" } | { kind: "scanned"; result: ScanResponse };

type Notice = { tone: "error" | "info"; message: string };

const textEncoder = new TextEncoder();

function scrollIntoView(id: string) {
  document.getElementById(id)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

export default function ScanView({ visible }: { visible: boolean }) {
  const { session, setSession, versionChoice, setVersionChoice } = useActiveSession();
  const [phase, setPhase] = useState<Phase>({ kind: "editing" });
  const [text, setText] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [selected, setSelected] = useState<number[]>([]);
  const [showSuppressions, setShowSuppressions] = useState(false);

  const abortRef = useRef<AbortController | null>(null);
  const scanTokenRef = useRef(0);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // The open session's version, or the one the next scan will start a session with.
  const versionId = session?.ruleSetVersionId ?? versionChoice;
  const version = useLoad(
    () => (versionId === null ? Promise.resolve(null) : getVersion(versionId)),
    [versionId],
  );
  const enabledRules =
    version.data?.rules.filter((rule) => rule.definition.enabled !== false).length ?? 0;
  const sessionId = session?.id ?? null;
  const suppressions = useLoad(
    () => (sessionId === null ? Promise.resolve([]) : listSuppressions(sessionId)),
    [sessionId],
  );
  const activeSuppressions =
    suppressions.data?.filter((suppression) => suppression.status === "active").length ?? null;

  const byteLength = useMemo(() => textEncoder.encode(text).length, [text]);
  const isBlank = text.trim() === "";
  const isTooLarge = byteLength > MAX_INPUT_BYTES;
  const noRulesEnabled = version.data !== null && enabledRules === 0;

  const result = phase.kind === "scanned" ? phase.result : null;
  const matches = useMemo(
    () =>
      (result?.findings ?? []).filter((finding): finding is SavedMatch => finding.kind === "match"),
    [result],
  );
  const ruleErrors = useMemo(
    () => (result?.findings ?? []).filter((finding) => finding.kind === "rule_error"),
    [result],
  );
  const highlights = useMemo(() => buildHighlights(text, matches), [text, matches]);
  const selectedHighlight =
    highlights.find((highlight) => selected.some((index) => highlight.findings.includes(index))) ??
    null;

  // Abort any in-flight scan when leaving the playground.
  useEffect(() => () => abortRef.current?.abort(), []);

  // Warn before a reload or close would throw away a running scan.
  useEffect(() => {
    if (phase.kind !== "scanning") return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [phase.kind]);

  // Results belong to the session they ran in; switching sessions clears them and stops a
  // running scan. The text is kept so it can be scanned in the new session.
  const previousSessionRef = useRef(sessionId);
  useEffect(() => {
    if (previousSessionRef.current === sessionId) return;
    previousSessionRef.current = sessionId;
    scanTokenRef.current += 1;
    abortRef.current?.abort();
    setSelected([]);
    setNotice(null);
    setShowSuppressions(false);
    setPhase({ kind: "editing" });
  }, [sessionId]);

  useEffect(() => {
    if (visible && phase.kind === "editing") inputRef.current?.focus();
  }, [visible, phase.kind]);

  // The guide's "Scan a sample now" opens Scan with ?sample=<index>.
  const [searchParams, setSearchParams] = useSearchParams();
  const sampleParam = visible ? searchParams.get("sample") : null;
  // biome-ignore lint/correctness/useExhaustiveDependencies: run once per link click.
  useEffect(() => {
    if (sampleParam === null) return;
    setSearchParams({}, { replace: true });
    const sample = SAMPLES[Number(sampleParam)];
    if (sample && phase.kind !== "scanning") replaceText(sample.text);
  }, [sampleParam]);

  /** True when it is fine to drop the current text: nothing typed, or it was already scanned. */
  function confirmDiscard(): boolean {
    return phase.kind !== "editing" || isBlank || window.confirm("Discard the text you entered?");
  }

  function replaceText(next: string) {
    if (!confirmDiscard()) return;
    setText(next);
    setNotice(null);
    setSelected([]);
    setPhase({ kind: "editing" });
  }

  /** Back to the editor with the scanned text, to change it and scan again. */
  function editText() {
    setNotice(null);
    setSelected([]);
    setPhase({ kind: "editing" });
  }

  /** Closes the session so the next scan can pick another rule set. The text stays. */
  function changeRuleSet() {
    if (session) setVersionChoice(session.ruleSetVersionId);
    setSession(null);
  }

  async function startScan() {
    if (!session && versionChoice === null) return;
    const controller = new AbortController();
    abortRef.current = controller;
    const token = ++scanTokenRef.current;
    setNotice(null);
    setSelected([]);
    setPhase({ kind: "scanning" });

    try {
      // The first scan starts the session. Marking it seen first keeps the session-change
      // effect from cancelling this scan.
      let target = session;
      if (!target) {
        target = await createSession(versionChoice as number);
        if (token !== scanTokenRef.current) return;
        previousSessionRef.current = target.id;
        setSession(target);
      }
      const response = await runScan(target.id, text, controller.signal);
      if (token !== scanTokenRef.current) return; // A newer scan or a cancel replaced this one.
      setPhase({ kind: "scanned", result: response });
    } catch (error) {
      if (token !== scanTokenRef.current) return;
      setPhase({ kind: "editing" });
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "The scan failed.",
      });
    }
  }

  function cancelScan() {
    scanTokenRef.current += 1;
    abortRef.current?.abort();
    setPhase({ kind: "editing" });
    setNotice({ tone: "info", message: "Scan cancelled. Your text is unchanged." });
  }

  /** Marks a finding's value as safe. This scan keeps the finding; later scans leave it out. */
  async function suppress(finding: SavedMatch, reason: string, expiresAt: string) {
    if (!session) return;
    await createSuppression(session.id, { findingId: finding.id, reason, expiresAt });
    suppressions.reload();
    setNotice({
      tone: "info",
      message: `Marked safe. Later scans in this session won't flag this value until ${formatDate(expiresAt)}.`,
    });
  }

  function selectHighlight(highlight: Highlight) {
    setSelected(highlight.findings);
    scrollIntoView(findingElementId(highlight.findings[0]));
  }

  function selectFinding(index: number) {
    setSelected([index]);
    const highlight = highlights.find((candidate) => candidate.findings.includes(index));
    if (highlight) scrollIntoView(highlightElementId(highlight));
  }

  const canScan = session !== null || versionChoice !== null;

  return (
    <div className="playground-section" hidden={!visible}>
      <SessionBar
        visible={visible}
        version={version.data}
        locked={phase.kind === "scanning"}
        onChangeRuleSet={changeRuleSet}
        activeSuppressions={activeSuppressions}
        showSuppressions={showSuppressions}
        onToggleSuppressions={() => setShowSuppressions((shown) => !shown)}
      />
      {session && showSuppressions && (
        <section className="panel">
          <SuppressionsPanel sessionId={session.id} suppressions={suppressions} />
        </section>
      )}

      <div className="playground-layout">
        <section className="panel scan-panel" aria-label="Scan">
          <div className="scan-toolbar">
            {phase.kind === "scanning" ? (
              <>
                <button type="button" className="button busy" disabled>
                  Scanning…
                </button>
                <button type="button" className="button danger" onClick={cancelScan}>
                  Cancel
                </button>
              </>
            ) : phase.kind === "scanned" ? (
              <>
                <button type="button" className="button primary" onClick={editText}>
                  Edit text
                </button>
                <button type="button" className="button" onClick={() => replaceText("")}>
                  Clear
                </button>
              </>
            ) : (
              <>
                <button
                  type="button"
                  className="button primary"
                  onClick={startScan}
                  disabled={!canScan || isBlank || isTooLarge || noRulesEnabled}
                >
                  Scan
                </button>
                {!isBlank && (
                  <button type="button" className="button" onClick={() => replaceText("")}>
                    Clear
                  </button>
                )}
              </>
            )}
            {phase.kind !== "scanning" && (
              <label>
                <span className="visually-hidden">Load a sample</span>
                <select
                  className="sample-select"
                  value=""
                  onChange={(event) => {
                    const sample = SAMPLES[Number(event.target.value)];
                    if (sample) replaceText(sample.text);
                  }}
                >
                  <option value="">Try a sample…</option>
                  {SAMPLES.map((sample, index) => (
                    <option key={sample.label} value={index}>
                      {sample.label}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <span className="scan-limits">
              {byteLength > 0 && `${byteLength.toLocaleString()} bytes · `}1 MB max · up to{" "}
              {MAX_FINDINGS} findings
            </span>
          </div>

          {noRulesEnabled && phase.kind === "editing" && (
            <p className="banner warning" role="status">
              No rules enabled in this rule set version, so a scan could only look clean.{" "}
              <Link to={`/playground/versions/${versionId}`}>Open the rule set</Link>
            </p>
          )}
          {phase.kind === "scanning" && (
            <p className="banner warning" role="status">
              Scanning — do not refresh or close this page.
            </p>
          )}
          {notice && (
            <p
              className={`banner ${notice.tone}`}
              role={notice.tone === "error" ? "alert" : "status"}
            >
              {notice.message}
            </p>
          )}
          {isTooLarge && phase.kind === "editing" && (
            <p className="banner error" role="alert">
              The text is {byteLength.toLocaleString()} bytes; the limit is 1 MB.
            </p>
          )}

          {phase.kind === "scanned" ? (
            <ScanText
              text={text}
              highlights={highlights}
              selected={selectedHighlight}
              onSelect={selectHighlight}
            />
          ) : (
            <textarea
              ref={inputRef}
              className="scan-input"
              aria-label="Text to scan"
              placeholder="Paste a config file, source file, or log here, or try a sample."
              spellCheck={false}
              autoComplete="off"
              value={text}
              readOnly={phase.kind === "scanning"}
              onChange={(event) => setText(event.target.value)}
            />
          )}
          <p className="muted small">Scan text is never saved; only the findings are.</p>
        </section>

        <aside className="panel results-panel" aria-label="Results">
          {result ? (
            <>
              {ruleErrors.length > 0 && (
                <div className="banner warning" role="alert">
                  <b>Partial scan:</b> {ruleErrors.length === 1 ? "a rule" : "some rules"} could not
                  run, so their results are missing.
                  <ul>
                    {ruleErrors.map((finding) => (
                      <li key={finding.id}>
                        {finding.violationPretty}{" "}
                        <Link to={`/playground/rules/${finding.ruleId}`}>Fix rule</Link>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {result.truncated && (
                <p className="banner warning" role="status">
                  More than {MAX_FINDINGS} findings: only the first {MAX_FINDINGS} are shown and
                  saved. A rule may be too broad.
                </p>
              )}
              {result.suppressedCount > 0 && (
                <p className="banner info" role="status">
                  {result.suppressedCount} {result.suppressedCount === 1 ? "value" : "values"}{" "}
                  marked safe {result.suppressedCount === 1 ? "was" : "were"} not flagged.{" "}
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => setShowSuppressions(true)}
                  >
                    See values marked safe
                  </button>
                </p>
              )}
              {matches.length === 0 ? (
                ruleErrors.length === 0 && (
                  <p className="banner success" role="status">
                    Nothing relevant found.
                  </p>
                )
              ) : (
                <FindingsList
                  findings={matches}
                  selected={selected}
                  onSelect={selectFinding}
                  suppressions={suppressions.data ?? []}
                  onSuppress={suppress}
                />
              )}
            </>
          ) : phase.kind === "scanning" ? (
            <p className="results-placeholder">Scanning…</p>
          ) : (
            <ol className="scan-steps">
              <li>
                <b>Paste text or try a sample.</b> Config files, source code and logs all work.
              </li>
              <li>
                <b>Scan it.</b> Each finding is highlighted in the text and listed here with why it
                was flagged and how to fix it.
              </li>
              <li>
                <b>Mark safe values.</b> Pick a finding that isn't a real secret and mark it as
                safe, so later scans in this session skip it.
              </li>
              <li>
                <b>Customize.</b> Change what's detected in{" "}
                <Link to="/playground/rules">Rules</Link>, and group rules in{" "}
                <Link to="/playground/rule-sets">Rule sets</Link>.
              </li>
            </ol>
          )}
        </aside>
      </div>
    </div>
  );
}
