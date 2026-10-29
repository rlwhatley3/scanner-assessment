import { useEffect } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { listSessions } from "../api.ts";
import { useLoad } from "../useLoad.ts";

/** Where /playground lands: the guide until the first scan has run, then Scan. */
export function PlaygroundHome() {
  const sessions = useLoad(listSessions, []);
  if (sessions.loading && !sessions.data && !sessions.error) return null;
  const scanned = sessions.data?.some((session) => session.scanCount > 0) ?? false;
  return <Navigate to={scanned ? "scan" : "guide"} replace />;
}

/** A small "?" that opens the guide at the section about the current tab. */
export function HelpLink({ section, label }: { section: string; label: string }) {
  return (
    <Link
      className="help-link"
      to={`/playground/guide#${section}`}
      title={label}
      aria-label={label}
    >
      ?
    </Link>
  );
}

const TERMS = [
  [
    "Rule",
    "One kind of secret to look for, like “AWS access key” or “a password after password=”.",
  ],
  ["Rule set", "A named group of rules. Every scan checks the text with one rule set."],
  [
    "Version",
    "A saved copy of a rule set. Changing a rule doesn't change past versions, so old results stay explainable.",
  ],
  [
    "Session",
    "A run of scans with the same rule set. It keeps each scan's results and the values you marked safe.",
  ],
  [
    "Marked safe",
    "A value you said isn't a real secret, like an example key. Later scans in the session skip it until it expires.",
  ],
  [
    "Severity",
    "How serious a finding is: High (a real key or password), Medium (probably a secret), Low (worth a look).",
  ],
];

export default function GuideView() {
  const navigate = useNavigate();
  const { hash } = useLocation();

  // Jump to the section a help link points at.
  useEffect(() => {
    if (hash) document.getElementById(hash.slice(1))?.scrollIntoView({ block: "start" });
  }, [hash]);

  return (
    <div className="playground-section">
      <article className="panel guide">
        <section className="guide-intro">
          <h2>Find secrets before they leak</h2>
          <p>
            Passwords, API keys and tokens often end up in config files, code and logs by accident.
            Paste text here and the scanner points out anything that looks like a secret, explains
            why, and says how to fix it.
          </p>
          <p className="muted small">
            Your text is never saved. Only the findings are kept: which rule matched and where,
            never the secret itself.
          </p>
        </section>

        <section id="start" className="guide-section">
          <h3>Quick start</h3>
          <ol className="guide-steps">
            <li>
              <b>Paste text</b> on the <Link to="/playground/scan">Scan</Link> tab, or pick one of
              the samples. They're made-up files full of fake secrets.
            </li>
            <li>
              <b>Click Scan.</b> Each finding is highlighted in the text and listed beside it.
            </li>
            <li>
              <b>Click a finding</b> to see why it was flagged and how to fix it.
            </li>
          </ol>
          <button
            type="button"
            className="button primary"
            onClick={() => navigate("/playground/scan?sample=0")}
          >
            Scan a sample now
          </button>
        </section>

        <section id="scan" className="guide-section">
          <h3>Scanning</h3>
          <dl className="guide-tasks">
            <dt>Check a file for secrets</dt>
            <dd>
              Open <Link to="/playground/scan">Scan</Link>, paste the text and click <b>Scan</b>. Up
              to 1 MB at a time.
            </dd>
            <dt>Change the text and scan again</dt>
            <dd>
              Click <b>Edit text</b> above the results. Your text stays, so you can fix it and scan
              again.
            </dd>
            <dt>A finding isn't a real secret</dt>
            <dd>
              Click the finding, then <b>Mark as safe…</b>, and say why. Later scans in the same
              session won't flag that value until the date you pick. To undo it, click{" "}
              <b>values marked safe</b> above the text and remove it.
            </dd>
            <dt>Scan with different rules</dt>
            <dd>
              Pick another rule set next to <b>Checking with</b>. If a scan already ran, click{" "}
              <b>Change rule set</b> first.
            </dd>
          </dl>
        </section>

        <section id="rules" className="guide-section">
          <h3>Rules: what counts as a secret</h3>
          <p>
            The scanner comes with built-in rules for common keys and passwords. Add your own for
            secrets only your team uses.
          </p>
          <dl className="guide-tasks">
            <dt>Catch your company's own token</dt>
            <dd>
              On <Link to="/playground/rules">Rules</Link>, click <b>New rule</b> and answer the
              questions: what to call it, what it looks like, how serious it is and how to fix it.
              Paste an example under <b>Check it with an example</b> to see if it works, then{" "}
              <b>Save</b>.
            </dd>
            <dt>Use your rule in scans</dt>
            <dd>
              Scans use rules through a rule set. Under <b>Where it's used</b>, pick a rule set and
              click <b>Add to set</b>.
            </dd>
            <dt>Change a rule that's already in use</dt>
            <dd>
              Edit it and <b>Save</b>, then click <b>Update</b> next to each rule set that uses it.
              Past scans keep the rules they ran with.
            </dd>
            <dt>Turn a rule off</dt>
            <dd>
              Untick <b>Turned on</b>, save, and update the rule sets that use it.
            </dd>
          </dl>
          <p className="muted small">
            <b>Advanced settings</b> on a rule shows every option the scanner has, such as custom
            patterns (regular expressions), randomness checks and checksums. You don't need them for
            most rules.
          </p>
        </section>

        <section id="rule-sets" className="guide-section">
          <h3>Rule sets</h3>
          <dl className="guide-tasks">
            <dt>Make a set for a project</dt>
            <dd>
              On <Link to="/playground/rule-sets">Rule sets</Link>, click <b>New rule set</b>, or
              copy an existing one from its <b>More…</b> menu.
            </dd>
            <dt>Scan with a set</dt>
            <dd>
              Click <b>Scan with this version</b>.
            </dd>
          </dl>
        </section>

        <section id="sessions" className="guide-section">
          <h3>Past results</h3>
          <p>
            <Link to="/playground/sessions">Sessions</Link> lists every session with its scans and
            findings. Click <b>Continue scanning</b> to keep going with the same rule set and the
            same values marked safe.
          </p>
        </section>

        <section id="mcp" className="guide-section">
          <h3>Use the scanner from an AI assistant</h3>
          <p>
            AI assistants like Claude Code can scan text and manage rules for you through MCP, a
            standard way for assistants to use other apps. The scanner offers it while it's running,
            to apps on this computer only.
          </p>
          <dl className="guide-tasks">
            <dt>Connect Claude Code</dt>
            <dd>
              With the scanner running, run this in a terminal:
              <pre className="guide-command">
                claude mcp add --transport http secrets-scanner http://127.0.0.1:3001/mcp
              </pre>
            </dd>
            <dt>Connect another app</dt>
            <dd>
              In the app's MCP settings, add a server named <b>secrets-scanner</b> with the address{" "}
              <code>http://127.0.0.1:3001/mcp</code> (type HTTP, sometimes called streamable HTTP).
            </dd>
            <dt>Check that it works</dt>
            <dd>
              Ask the assistant “list the scanner's rule sets”. In Claude Code,{" "}
              <code>claude mcp list</code> should show <b>secrets-scanner</b> as connected.
            </dd>
            <dt>It won't connect</dt>
            <dd>
              Make sure the scanner is running and the app is on this computer. If you started the
              scanner with a different <code>API_PORT</code>, use that number instead of 3001.
            </dd>
          </dl>
          <p className="muted small">
            See <Link to="/mcp-docs">MCP docs</Link> for every tool the assistant can use.
          </p>
        </section>

        <section id="words" className="guide-section">
          <h3>Words you'll see</h3>
          <dl className="guide-terms">
            {TERMS.map(([term, meaning]) => (
              <div key={term}>
                <dt>{term}</dt>
                <dd>{meaning}</dd>
              </div>
            ))}
          </dl>
        </section>
      </article>
    </div>
  );
}
