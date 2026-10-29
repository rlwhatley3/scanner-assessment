import { Link } from "react-router-dom";
import type { RuleTiming, SlowRule } from "../api.ts";

/** Names the rules that matched almost everything in a scan, in plain words. */
export function SlowRulesNote({ slowRules }: { slowRules: SlowRule[] }) {
  if (slowRules.length === 0) return null;
  return (
    <div className="banner warning" role="status">
      <b>Slow scan:</b> {slowRules.length === 1 ? "a rule matches" : "some rules match"} almost
      everything in this text, which slows down every scan.
      <ul>
        {slowRules.map((rule) => (
          <li key={rule.ruleId}>
            {rule.ruleName} matched {rule.matches.toLocaleString()} times.{" "}
            <Link to={`/playground/rules/${rule.ruleId}`}>Make it more specific</Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

function milliseconds(micros: number): string {
  return micros < 100 ? "under 0.1 ms" : `${(micros / 1000).toFixed(1)} ms`;
}

/** How long each rule took and how often it matched, slowest first. */
export function RuleTimingsTable({ timings }: { timings: RuleTiming[] }) {
  const slowestFirst = [...timings].sort((a, b) => b.micros - a.micros);
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Rule</th>
          <th>Time</th>
          <th>Matches</th>
        </tr>
      </thead>
      <tbody>
        {slowestFirst.map((timing) => (
          <tr key={timing.ruleId}>
            <td>
              {timing.ruleName}
              {timing.floods && <span className="badge">Matches almost everything</span>}
            </td>
            <td>{milliseconds(timing.micros)}</td>
            <td>{timing.matches.toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
