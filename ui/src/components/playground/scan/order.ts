import type { MatchDetails } from "../api.ts";

/** Whether the match looks like an example rather than a real secret, from its placeholder
 * score or any model's or value classifier's verdict. */
export function looksLikeExample(details: MatchDetails): boolean {
  return (
    (details.placeholderScore ?? 0) >= 50 ||
    details.valueClass?.label === "placeholder" ||
    (details.modelAssessments?.some((assessment) => assessment.verdict === "likely_example") ??
      false)
  );
}

/**
 * Indices into `findings`, the ones most likely to be real secrets first: everything that
 * doesn't look like an example comes before everything that does, then higher confidence comes
 * first. Ties keep text order.
 */
export function likelyRealOrder(findings: { violation: MatchDetails }[]): number[] {
  const examples = findings.map(({ violation }) => looksLikeExample(violation));
  return findings
    .map((_, index) => index)
    .sort(
      (a, b) =>
        Number(examples[a]) - Number(examples[b]) ||
        findings[b].violation.confidence - findings[a].violation.confidence ||
        a - b,
    );
}
