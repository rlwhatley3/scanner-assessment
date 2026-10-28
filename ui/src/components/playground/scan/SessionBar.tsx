import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  createSession,
  getRuleSet,
  listRuleSets,
  type RuleSetVersionDetail,
  versionLabel,
} from "../api.ts";
import { useActiveSession } from "../session.tsx";
import { useLoad } from "../useLoad.ts";

interface SessionBarProps {
  visible: boolean;
  version: RuleSetVersionDetail | null;
  /** True while a scan is running, so the session cannot change under it. */
  locked: boolean;
  onLeave: () => void;
}

/** Shows the active scan session, or lets the user start one on a rule set's version. */
export default function SessionBar({ visible, version, locked, onLeave }: SessionBarProps) {
  const { session, setSession } = useActiveSession();
  const ruleSets = useLoad(() => listRuleSets(), [visible, session === null]);
  const [ruleSetId, setRuleSetId] = useState<number | null>(null);
  const ruleSet = useLoad(
    () => (ruleSetId === null ? Promise.resolve(null) : getRuleSet(ruleSetId)),
    [ruleSetId, visible],
  );
  const [choice, setChoice] = useState<number | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Only sets with a version that isn't archived can start a session.
  const sets = (ruleSets.data ?? []).filter((candidate) => candidate.latestVersionId !== null);
  const versions = (ruleSet.data?.id === ruleSetId ? ruleSet.data.versions : []).filter(
    (candidate) => !candidate.archived,
  );

  // Default to the first set, then to its newest version.
  useEffect(() => {
    if (!sets.some((candidate) => candidate.id === ruleSetId)) setRuleSetId(sets[0]?.id ?? null);
  }, [sets, ruleSetId]);
  useEffect(() => {
    if (!versions.some((candidate) => candidate.id === choice)) {
      setChoice(versions.at(-1)?.id ?? null);
    }
  }, [versions, choice]);

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
          <b>Scan session {session.id}</b> ·{" "}
          <Link
            to={`/playground/rule-sets/${session.ruleSetId}/versions/${session.ruleSetVersionId}`}
          >
            {versionLabel({ ruleSetName: session.ruleSetName, number: session.versionNumber })}
          </Link>
          {enabled !== undefined && ` · ${enabled} ${enabled === 1 ? "rule" : "rules"} enabled`}
        </span>
        <button type="button" className="button" onClick={onLeave} disabled={locked}>
          Close session
        </button>
      </div>
    );
  }

  return (
    <section className="panel playground-empty">
      <h2>Start a scan session</h2>
      {ruleSets.error ? (
        <p className="banner error" role="alert">
          {ruleSets.error}{" "}
          <button type="button" className="link-button" onClick={ruleSets.reload}>
            Retry
          </button>
        </p>
      ) : sets.length === 0 && !ruleSets.loading ? (
        <p>
          No rule set has a version to scan with yet. Write some{" "}
          <Link to="/playground/rules">rules</Link>, then save them as a version of a rule set in{" "}
          <Link to="/playground/rule-sets">Rule sets</Link>.
        </p>
      ) : (
        <>
          <p>
            A session scans with one version of a rule set and keeps every scan's results. You can
            also <Link to="/playground/sessions">reopen a past session</Link>.
          </p>
          <div className="inline-form">
            <label>
              Rule set{" "}
              <select
                value={ruleSetId ?? ""}
                onChange={(event) => setRuleSetId(Number(event.target.value))}
              >
                {sets.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    {candidate.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Version{" "}
              <select
                value={choice ?? ""}
                onChange={(event) => setChoice(Number(event.target.value))}
              >
                {[...versions].reverse().map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    v{candidate.number}
                    {candidate.id === versions.at(-1)?.id ? " (latest)" : ""} ·{" "}
                    {candidate.ruleCount} {candidate.ruleCount === 1 ? "rule" : "rules"}
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
