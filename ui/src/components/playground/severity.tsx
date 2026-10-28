import type { DetectionType, Severity } from "./api.ts";

export const SEVERITY_LABELS: Record<Severity, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };

export const DETECTION_LABELS: Record<DetectionType, string> = {
  direct_credential: "Direct credential",
  likely_credential: "Likely credential",
  unsafe_handling: "Unsafe handling",
};

// A distinct shape per tone, so severity never depends on color alone.
const ICONS: Record<Severity | "overlap", string> = {
  high: "▲",
  medium: "◆",
  low: "●",
  overlap: "◎",
};

export function SeverityIcon({ tone }: { tone: Severity | "overlap" }) {
  return (
    <span className={`severity-icon tone-${tone}`} aria-hidden="true">
      {ICONS[tone]}
    </span>
  );
}
