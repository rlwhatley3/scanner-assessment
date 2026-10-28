import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { createSession, listVersions, type RuleSetVersionDetail } from "../api.ts";
import { useActiveSession } from "../session.tsx";
import { useLoad } from "../useLoad.ts";

interface SessionBarProps {
  visible: boolean;
  version: RuleSetVersionDetail | null;
  /** True while a scan is running, so the session cannot change under it. */
  locked: boolean;
  onLeave: () => void;
}

/** Shows the active scan session, or lets the user start one on a rule set version. */
export default function SessionBar({ visible, version, locked, onLeave }: SessionBarProps) {
  const { session, setSession } = useActiveSession();
  const versions = useLoad(() => listVersions(), [visible, session === null]);
  const [choice, setChoice] = useState<number | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Default to the newest version once the list arrives.
  useEffect(() => {
    const list = versions.data ?? [];
    if (!list.some((candidate) => candidate.id === choice)) setChoice(list.at(-1)?.id ?? null);
  }, [versions.data, choice]);

  async function start() {
    if (choice === null) return;
    setStarting(true);
    setError(null);
    try {
      setSession(await createSession(choice));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not start the session.");
    } finally {
      setStarting(false);
    }
  }

  if (session) {
    const enabled = version?.rules.filter((rule) => rule.definition.enabled !== false).length;
    return (
      <div className="session-bar panel">
        <span>
          <b>Scan session {session.id}</b> · Rule set{" "}
          <Link to={`/playground/rule-sets/${session.ruleSetVersionId}`}>
            version {session.ruleSetVersionId}
          </Link>
          {enabled !== undefined && ` · ${enabled} ${enabled === 1 ? "rule" : "rules"} enabled`}
        </span>
        <button type="button" className="button" onClick={onLeave} disabled={locked}>
          Close session
        </button>
      </div>
    );
  }

  const list = versions.data ?? [];
  return (
    <section className="panel playground-empty">
      <h2>Start a scan session</h2>
      {versions.error ? (
        <p className="banner error" role="alert">
          {versions.error}{" "}
          <button type="button" className="link-button" onClick={versions.reload}>
            Retry
          </button>
        </p>
      ) : list.length === 0 && !versions.loading ? (
        <p>
          There are no rule set versions yet. Write some <Link to="/playground/rules">rules</Link>,
          then save them as a version in <Link to="/playground/rule-sets">Rule sets</Link>.
        </p>
      ) : (
        <>
          <p>
            A session scans with one rule set version and keeps every scan's results. You can also{" "}
            <Link to="/playground/sessions">reopen a past session</Link>.
          </p>
          <div className="inline-form">
            <label>
              Rule set version{" "}
              <select
                value={choice ?? ""}
                onChange={(event) => setChoice(Number(event.target.value))}
              >
                {list.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    Version {candidate.id} ({candidate.ruleCount}{" "}
                    {candidate.ruleCount === 1 ? "rule" : "rules"})
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="button primary"
              onClick={start}
              disabled={choice === null || starting}
            >
              Start session
            </button>
          </div>
        </>
      )}
      {error && (
        <p className="banner error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
