import type { DetectionType, Severity } from "./api.ts";
import type { HighlightTone } from "./scan/highlights.ts";

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
  placeholder_vs_real: "Placeholder vs. real",
  model_assessment: "Model assessment",
  model_detection: "Model detection",
};

// A distinct shape per tone, so severity never depends on color alone.
const ICONS: Record<HighlightTone, string> = {
  high: "▲",
  medium: "◆",
  low: "●",
  overlap: "◎",
  suppressed: "○",
};

export function SeverityIcon({ tone }: { tone: HighlightTone }) {
  return (
    <span className={`severity-icon tone-${tone}`} aria-hidden="true">
      {ICONS[tone]}
    </span>
  );
}
