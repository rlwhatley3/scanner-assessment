import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  ApiError,
  createVersion,
  getVersion,
  listRuleSets,
  type Rule,
  type RuleSet,
  type RuleSetVersionDetail,
} from "../api.ts";
import { versionPath } from "../rule-sets/RuleSetPanel.tsx";
import { useLoad } from "../useLoad.ts";

interface RuleSetMembershipProps {
  /** The rule as saved. */
  rule: Rule;
  /** True while the form has unsaved changes, which a new version would not include. */
  dirty: boolean;
  /** A version was saved, so the rule's version list changed. */
  onChanged: () => void;
}

interface SetState {
  set: RuleSet;
  latest: RuleSetVersionDetail | null;
}

/** Which rule sets use this rule, whether their newest version has its saved copy, and a way to
 * add it to another set. Each action saves a new version of the set. */
export default function RuleSetMembership({ rule, dirty, onChanged }: RuleSetMembershipProps) {
  const [generation, setGeneration] = useState(0);
  const sets = useLoad(async (): Promise<SetState[]> => {
    const all = await listRuleSets();
    return Promise.all(
      all.map(async (set) => ({
        set,
        latest: set.latestVersionId === null ? null : await getVersion(set.latestVersionId),
      })),
    );
  }, [rule.id, generation]);
  const [addTo, setAddTo] = useState<number | "">("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "error" | "success"; message: string } | null>(null);
  const [saved, setSaved] = useState<RuleSetVersionDetail | null>(null);

  const current = JSON.stringify(rule.definition);
  // A later save of the rule makes the last message about a saved version out of date.
  // biome-ignore lint/correctness/useExhaustiveDependencies: clear only when the rule changes.
  useEffect(() => {
    setSaved(null);
    setNotice(null);
  }, [current]);
  const using = (sets.data ?? []).flatMap(({ set, latest }) => {
    const snapshot = latest?.rules.find((entry) => entry.ruleId === rule.id);
    return latest && snapshot
      ? [{ set, latest, stale: JSON.stringify(snapshot.definition) !== current }]
      : [];
  });
  const others = (sets.data ?? []).filter(
    ({ latest }) => !latest?.rules.some((entry) => entry.ruleId === rule.id),
  );

  async function saveVersion(set: RuleSet, latest: RuleSetVersionDetail | null, add: boolean) {
    setBusy(true);
    setNotice(null);
    setSaved(null);
    const ruleIds = [
      ...(latest?.rules.map((entry) => entry.ruleId) ?? []),
      ...(add ? [rule.id] : []),
    ];
    try {
      const version = await createVersion(set.id, ruleIds, latest?.id ?? null);
      setSaved(version);
      setAddTo("");
      setGeneration((value) => value + 1);
      onChanged();
    } catch (error) {
      const details =
        error instanceof ApiError && error.errors.length > 0
          ? ` ${error.errors.map((problem) => problem.message).join(" ")}`
          : "";
      setNotice({
        tone: "error",
        message: `${error instanceof Error ? error.message : "Could not save the version."}${details}`,
      });
    } finally {
      setBusy(false);
    }
  }

  const blocked = dirty || busy;
  const blockedTitle = dirty ? "Save your changes to the rule first." : undefined;

  return (
    <section className="rule-membership" aria-label="Where this rule is used">
      <h3>Where it's used</h3>
      <p className="muted small">
        Scans use rules through a rule set, a named group of rules. Add this rule to one to scan
        with it.
      </p>
      {sets.error && (
        <p className="banner error" role="alert">
          {sets.error}
        </p>
      )}
      {sets.data && using.length === 0 && (
        <p className="banner info" role="status">
          Not used in scans yet.
        </p>
      )}
      {using.length > 0 && (
        <ul className="membership-list">
          {using.map(({ set, latest, stale }) => (
            <li key={set.id}>
              <Link to={versionPath(set.id, latest.id)}>{set.name}</Link>
              {stale ? (
                <>
                  <span className="muted small">
                    still uses your previous version of this rule.
                  </span>
                  <button
                    type="button"
                    className="button primary"
                    onClick={() => saveVersion(set, latest, false)}
                    disabled={blocked}
                    title={blockedTitle}
                  >
                    Update {set.name}
                  </button>
                </>
              ) : (
                <span className="muted small">uses this rule as saved.</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {others.length > 0 && (
        <div className="inline-form">
          <label>
            <span className="visually-hidden">Rule set to add this rule to</span>
            <select
              value={addTo}
              onChange={(event) => setAddTo(event.target.value ? Number(event.target.value) : "")}
            >
              <option value="">Add to a rule set…</option>
              {others.map(({ set }) => (
                <option key={set.id} value={set.id}>
                  {set.name}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            className="button"
            disabled={addTo === "" || blocked}
            title={blockedTitle}
            onClick={() => {
              const target = others.find(({ set }) => set.id === addTo);
              if (target) saveVersion(target.set, target.latest, true);
            }}
          >
            Add to set
          </button>
        </div>
      )}
      {(using.length > 0 || others.length > 0) && (
        <p className="muted small">
          Past scans aren't affected: they keep the rules they ran with.
        </p>
      )}
      {saved && (
        <p className="banner success" role="status">
          Updated <Link to={versionPath(saved.ruleSetId, saved.id)}>{saved.ruleSetName}</Link>. New
          scans with it use this rule as saved.
        </p>
      )}
      {notice && (
        <p className={`banner ${notice.tone}`} role={notice.tone === "error" ? "alert" : "status"}>
          {notice.message}
        </p>
      )}
    </section>
  );
}
