import type { DetectionType, Model } from "../api.ts";

/**
 * Whether the rule form offers a detection type. A model rule type is offered only when a loaded
 * model fits it, so nobody picks a type they can't finish. The rule's own type always stays, and
 * every type shows until the models are known.
 */
export function offersDetectionType(
  type: DetectionType,
  models: readonly Model[] | null,
  current: DetectionType | "",
): boolean {
  if (type !== "model_assessment" && type !== "model_detection") return true;
  if (models === null || type === current) return true;
  return models.some((model) => model.uses.includes(type));
}
