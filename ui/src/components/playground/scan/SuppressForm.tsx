import { type FormEvent, useId, useMemo, useState } from "react";
import { expiryBounds, expiryFromDate } from "./suppressions.ts";

interface SuppressFormProps {
  /** Saves the suppression; a rejection is shown in the form. */
  onSubmit: (reason: string, expiresAt: string) => Promise<void>;
  onCancel: () => void;
}

/** Asks why a finding's value is safe and until when, then suppresses it in the session. */
export default function SuppressForm({ onSubmit, onCancel }: SuppressFormProps) {
  const bounds = useMemo(() => expiryBounds(new Date()), []);
  const [reason, setReason] = useState("");
  const [date, setDate] = useState(bounds.initial);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const id = useId();

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await onSubmit(reason.trim(), expiryFromDate(date));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not suppress the finding.");
      setSaving(false);
    }
  }

  return (
    <form className="suppress-form" onSubmit={submit}>
      <p className="muted small suppress-note">
        Later scans in this session won't flag this exact value from this rule. If the value
        changes, or the suppression expires or is removed, it is flagged again. Other sessions are
        not affected. Never type the value itself here.
      </p>
      <label htmlFor={`${id}-reason`}>Why is it safe?</label>
      <textarea
        id={`${id}-reason`}
        rows={2}
        maxLength={500}
        required
        placeholder="e.g. Example key from the AWS docs, used in our README"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
      />
      <label htmlFor={`${id}-expires`}>Expires after</label>
      <input
        id={`${id}-expires`}
        type="date"
        required
        min={bounds.min}
        max={bounds.max}
        value={date}
        onChange={(event) => setDate(event.target.value)}
      />
      {error && (
        <p className="banner error" role="alert">
          {error}
        </p>
      )}
      <div className="form-actions">
        <button
          type="submit"
          className="button primary"
          disabled={saving || reason.trim() === "" || date === ""}
        >
          Suppress
        </button>
        <button type="button" className="button" onClick={onCancel} disabled={saving}>
          Cancel
        </button>
      </div>
    </form>
  );
}
