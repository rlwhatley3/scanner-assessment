import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getRuleSet, listRuleSets, type RuleSetVersionDetail, versionLabel } from "../api.ts";
import { HelpLink } from "../guide/GuideView.tsx";
import { useActiveSession } from "../session.tsx";
import { useLoad } from "../useLoad.ts";

interface SessionBarProps {
  visible: boolean;
  version: RuleSetVersionDetail | null;
  /** True while a scan is running, so the rule set cannot change under it. */
  locked: boolean;
  /** Closes the session so the next scan can use another rule set; the text stays. */
  onChangeRuleSet: () => void;
  /** Values marked safe that apply to the next scan; null until loaded. */
  activeSuppressions: number | null;
  showSuppressions: boolean;
  onToggleSuppressions: () => void;
}

/** What the next scan checks with: the open session's version, or a version to start one on. */
export default function SessionBar({
  visible,
  version,
  locked,
  onChangeRuleSet,
  activeSuppressions,
  showSuppressions,
  onToggleSuppressions,
}: SessionBarProps) {
  const { session, versionChoice, setVersionChoice } = useActiveSession();
  const ruleSets = useLoad(() => listRuleSets(), [visible, session === null]);
  // Only sets with a version that isn't archived can start a session.
  const sets = (ruleSets.data ?? []).filter((candidate) => candidate.latestVersionId !== null);
  const [ruleSetId, setRuleSetId] = useState<number | null>(null);
  const ruleSet = useLoad(
    () => (ruleSetId === null ? Promise.resolve(null) : getRuleSet(ruleSetId)),
    [ruleSetId, visible],
  );
  const versions = (ruleSet.data?.id === ruleSetId ? ruleSet.data.versions : []).filter(
    (candidate) => !candidate.archived,
  );

  // Follow the chosen version's set (e.g. after "Scan with this version"), else the first set.
  useEffect(() => {
    if (session || ruleSets.data === null) return;
    const chosen = version && version.id === versionChoice ? version.ruleSetId : null;
    const wanted = chosen ?? (sets.some((set) => set.id === ruleSetId) ? ruleSetId : null);
    setRuleSetId(wanted ?? sets[0]?.id ?? null);
  }, [session, ruleSets.data, sets, version, versionChoice, ruleSetId]);
  // Default to the set's newest version. A choice from another set is kept while its version
  // loads, since the effect above then switches to that set.
  useEffect(() => {
    if (session || ruleSet.data?.id !== ruleSetId) return;
    if (versions.some((candidate) => candidate.id === versionChoice)) return;
    const otherSet =
      versionChoice !== null && (version?.id !== versionChoice || version.ruleSetId !== ruleSetId);
    if (!otherSet) setVersionChoice(versions.at(-1)?.id ?? null);
  }, [session, ruleSet.data, ruleSetId, versions, versionChoice, version, setVersionChoice]);

  const enabled = version?.rules.filter((rule) => rule.definition.enabled !== false).length;
  const ruleCount = enabled !== undefined && (
    <span className="muted">
      {enabled} {enabled === 1 ? "rule" : "rules"} enabled
    </span>
  );

  if (session) {
    return (
      <div className="session-bar panel">
        <span className="session-bar-summary">
          <span>
            Checking with{" "}
            <Link
              to={`/playground/rule-sets/${session.ruleSetId}/versions/${session.ruleSetVersionId}`}
            >
              {versionLabel({ ruleSetName: session.ruleSetName, number: session.versionNumber })}
            </Link>
          </span>
          {ruleCount}
          <span className="muted">Session {session.id}</span>
          <button
            type="button"
            className="link-button"
            aria-expanded={showSuppressions}
            onClick={onToggleSuppressions}
          >
            {activeSuppressions === null
              ? "Values marked safe"
              : `${activeSuppressions} ${activeSuppressions === 1 ? "value" : "values"} marked safe`}
          </button>
        </span>
        <span className="session-bar-summary">
          <button type="button" className="button" onClick={onChangeRuleSet} disabled={locked}>
            Change rule set
          </button>
          <HelpLink section="scan" label="How scanning works" />
        </span>
      </div>
    );
  }

  if (ruleSets.error) {
    return (
      <p className="banner error" role="alert">
        {ruleSets.error}{" "}
        <button type="button" className="link-button" onClick={ruleSets.reload}>
          Retry
        </button>
      </p>
    );
  }

  if (sets.length === 0 && !ruleSets.loading) {
    return (
      <p className="banner warning" role="status">
        No rule set has a version to scan with yet. Write some{" "}
        <Link to="/playground/rules">rules</Link>, then save them as a version in{" "}
        <Link to="/playground/rule-sets">Rule sets</Link>.
      </p>
    );
  }

  return (
    <div className="session-bar panel">
      <span className="session-bar-summary">
        <label>
          Checking with{" "}
          <select
            value={ruleSetId ?? ""}
            disabled={locked}
            onChange={(event) => {
              setRuleSetId(Number(event.target.value));
              setVersionChoice(null);
            }}
          >
            {sets.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="visually-hidden">Version</span>
          <select
            value={versionChoice ?? ""}
            disabled={locked}
            onChange={(event) => setVersionChoice(Number(event.target.value))}
          >
            {[...versions].reverse().map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                v{candidate.number}
                {candidate.id === versions.at(-1)?.id ? " (latest)" : ""}
              </option>
            ))}
          </select>
        </label>
        {ruleCount}
      </span>
      <span className="session-bar-summary">
        <Link className="link-button" to="/playground/sessions">
          Continue a past session
        </Link>
        <HelpLink section="scan" label="How scanning works" />
      </span>
    </div>
  );
}
