import { useState } from "react";
import { formatDate, removeSuppression, type Suppression } from "../api.ts";
import type { Loaded } from "../useLoad.ts";

interface SuppressionsPanelProps {
  sessionId: number;
  suppressions: Loaded<Suppression[]>;
}

const STATUS_LABELS: Record<Suppression["status"], string> = {
  active: "Active",
  expired: "Expired",
  removed: "Removed",
};

/** A session's suppressions, newest first, with a way to remove the active ones. */
export default function SuppressionsPanel({ sessionId, suppressions }: SuppressionsPanelProps) {
  const [removing, setRemoving] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function remove(suppression: Suppression) {
    setRemoving(suppression.id);
    setError(null);
    try {
      await removeSuppression(sessionId, suppression.id);
      suppressions.reload();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not remove the suppression.");
    } finally {
      setRemoving(null);
    }
  }

  const list = suppressions.data ?? [];
  return (
    <section className="suppressions" aria-label="Suppressions">
      <h3>Suppressions</h3>
      <p className="muted small">
        Each one covers one value found by one rule in this session. Removing one keeps it on
        record, so past scans still show why their findings were suppressed.
      </p>
      {(error ?? suppressions.error) && (
        <p className="banner error" role="alert">
          {error ?? suppressions.error}
        </p>
      )}
      {list.length === 0 ? (
        !suppressions.loading && <p className="muted">No suppressions in this session.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Reason</th>
              <th>Status</th>
              <th>Expires</th>
              <th>Marked</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {list.map((suppression) => (
              <tr key={suppression.id} className={suppression.status === "active" ? "" : "muted"}>
                <td>
                  {suppression.ruleName}
                  <span className="muted small"> · from scan {suppression.scanId}</span>
                </td>
                <td>{suppression.reason}</td>
                <td>
                  <span className={`badge status-${suppression.status}`}>
                    {STATUS_LABELS[suppression.status]}
                  </span>
                </td>
                <td>{formatDate(suppression.expiresAt)}</td>
                <td>
                  {suppression.suppressedCount}{" "}
                  {suppression.suppressedCount === 1 ? "finding" : "findings"}
                </td>
                <td>
                  {suppression.status === "active" && (
                    <button
                      type="button"
                      className="button"
                      onClick={() => remove(suppression)}
                      disabled={removing !== null}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
