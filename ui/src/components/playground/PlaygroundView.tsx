import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  MAX_FINDINGS,
  MAX_INPUT_BYTES,
  type MatchFinding,
  runScan,
  type ScanResponse,
} from "./api.ts";
import FindingsList, { findingElementId } from "./FindingsList.tsx";
import { buildHighlights, type Highlight } from "./highlights.ts";
import ScanText, { highlightElementId } from "./ScanText.tsx";
import { useApiHealth } from "./useApiHealth.ts";
import "./style.css";

// The scan text lives only in component state: never in storage, the URL, or a log.
type Phase =
  | { kind: "none" }
  | { kind: "editing" }
  | { kind: "scanning" }
  | { kind: "scanned"; result: ScanResponse };

type Notice = { tone: "error" | "info"; message: string };

const CANCEL_WINDOW_MS = 5_000;
const textEncoder = new TextEncoder();

function scrollIntoView(id: string) {
  document.getElementById(id)?.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

export default function PlaygroundView() {
  const health = useApiHealth();
  const [phase, setPhase] = useState<Phase>({ kind: "none" });
  const [text, setText] = useState("");
  const [notice, setNotice] = useState<Notice | null>(null);
  const [cancelArmed, setCancelArmed] = useState(false);
  const [selected, setSelected] = useState<number[]>([]);

  const abortRef = useRef<AbortController | null>(null);
  const scanTokenRef = useRef(0);
  const cancelTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const byteLength = useMemo(() => textEncoder.encode(text).length, [text]);
  const isBlank = text.trim() === "";
  const isTooLarge = byteLength > MAX_INPUT_BYTES;

  const result = phase.kind === "scanned" ? phase.result : null;
  const matches = useMemo(
    () =>
      (result?.findings ?? []).filter(
        (finding): finding is MatchFinding => finding.kind === "match",
      ),
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

  const disarmCancel = useCallback(() => {
    clearTimeout(cancelTimerRef.current);
    setCancelArmed(false);
  }, []);

  const armCancel = useCallback(() => {
    clearTimeout(cancelTimerRef.current);
    setCancelArmed(true);
    cancelTimerRef.current = setTimeout(() => setCancelArmed(false), CANCEL_WINDOW_MS);
  }, []);

  // Abort any in-flight scan when leaving the page.
  useEffect(
    () => () => {
      abortRef.current?.abort();
      clearTimeout(cancelTimerRef.current);
    },
    [],
  );

  // Warn before a reload or close would throw away a running scan.
  useEffect(() => {
    if (phase.kind !== "scanning") return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [phase.kind]);

  useEffect(() => {
    if (phase.kind === "editing") inputRef.current?.focus();
  }, [phase.kind]);

  function startNewScan() {
    if (phase.kind === "editing" && !isBlank && !window.confirm("Discard current scan?")) return;
    setText("");
    setNotice(null);
    setSelected([]);
    setPhase({ kind: "editing" });
  }

  async function startScan() {
    const controller = new AbortController();
    abortRef.current = controller;
    const token = ++scanTokenRef.current;
    setNotice(null);
    setSelected([]);
    setPhase({ kind: "scanning" });
    armCancel();

    try {
      const response = await runScan(text, controller.signal);
      if (token !== scanTokenRef.current) return; // A newer scan or a cancel replaced this one.
      setPhase({ kind: "scanned", result: response });
    } catch (error) {
      if (token !== scanTokenRef.current) return;
      setPhase({ kind: "editing" });
      setNotice({
        tone: "error",
        message: error instanceof Error ? error.message : "The scan failed.",
      });
    } finally {
      if (token === scanTokenRef.current) disarmCancel();
    }
  }

  function cancelScan() {
    scanTokenRef.current += 1;
    abortRef.current?.abort();
    disarmCancel();
    setPhase({ kind: "editing" });
    setNotice({ tone: "info", message: "Scan cancelled. Your text is unchanged." });
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

  return (
    <main className="page-content playground">
      <header className="playground-header">
        <div>
          <h1>Secrets Scanner Playground</h1>
          <p className="intro">
            Paste text to scan it for secrets. Scan text is never saved; only results are.
          </p>
        </div>
        <span className={`api-status ${health}`} role="status">
          <span className="status" aria-hidden="true" />
          {health === "checking"
            ? "Checking API…"
            : health === "online"
              ? "API connected"
              : "API unreachable"}
        </span>
      </header>

      {phase.kind === "none" ? (
        <section className="panel playground-empty">
          <h2>No scan open</h2>
          <p>Start a new scan to paste text and check it against the rule set.</p>
          <button type="button" className="button primary" onClick={startNewScan}>
            New scan
          </button>
        </section>
      ) : (
        <div className="playground-layout">
          <section className="panel scan-panel" aria-label="Scan">
            <div className="scan-toolbar">
              <button
                type="button"
                className="button"
                onClick={startNewScan}
                disabled={phase.kind === "scanning"}
              >
                New scan
              </button>
              {phase.kind === "scanning" ? (
                <button
                  type="button"
                  className={`button ${cancelArmed ? "danger" : "busy"}`}
                  onClick={cancelArmed ? cancelScan : armCancel}
                >
                  {cancelArmed ? "Cancel" : "Scanning…"}
                </button>
              ) : (
                phase.kind === "editing" && (
                  <button
                    type="button"
                    className="button primary"
                    onClick={startScan}
                    disabled={isBlank || isTooLarge}
                  >
                    Scan
                  </button>
                )
              )}
              <span className="scan-limits">Up to {MAX_FINDINGS} findings per scan · 1 MB max</span>
            </div>

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
                placeholder="Paste a config file, source file, or snippet…"
                spellCheck={false}
                autoComplete="off"
                value={text}
                readOnly={phase.kind === "scanning"}
                onChange={(event) => setText(event.target.value)}
              />
            )}
          </section>

          <aside className="panel results-panel" aria-label="Results">
            {result ? (
              <>
                {ruleErrors.length > 0 && (
                  <div className="banner warning" role="alert">
                    <b>Partial scan:</b> {ruleErrors.length === 1 ? "a rule" : "some rules"} could
                    not run, so their results are missing.
                    <ul>
                      {ruleErrors.map((finding) => (
                        <li key={finding.rule_id}>{finding.violation_pretty}</li>
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
                {matches.length === 0 ? (
                  ruleErrors.length === 0 && (
                    <p className="banner success" role="status">
                      Nothing relevant found.
                    </p>
                  )
                ) : (
                  <FindingsList findings={matches} selected={selected} onSelect={selectFinding} />
                )}
              </>
            ) : (
              <p className="results-placeholder">
                {phase.kind === "scanning" ? "Scanning…" : "Results appear here after a scan."}
              </p>
            )}
          </aside>
        </div>
      )}
    </main>
  );
}
