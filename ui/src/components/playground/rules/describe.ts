import type { RuleDefinition } from "../api.ts";
import { CHARSETS, shapeOf } from "./shape.ts";

/** The first few names, e.g. "password, secret, token and 13 more". */
function someOf(names: string[], shown = 3): string {
  const list = names.map((name) => name.trim()).filter(Boolean);
  const rest = list.length - shown;
  return list.slice(0, shown).join(", ") + (rest > 0 ? ` and ${rest} more` : "");
}

/** What a rule looks for, in one plain sentence, for lists that can't show the pattern. */
export function describeRule(definition: RuleDefinition): string {
  const shape = shapeOf({
    pattern: definition.pattern ?? "",
    keyNames: (definition.keyNames ?? []).join(", "),
    detectionType: definition.detectionType ?? "",
  });
  if (definition.pattern && shape.kind === "prefix") {
    const start = shape.prefix ? `Text starting with “${shape.prefix}”, then` : "Runs of";
    return `${start} ${shape.length} ${CHARSETS[shape.charset].label}.`;
  }
  if (shape.kind === "label") {
    return `Values after labels like ${someOf(shape.labels.split(",")) || "password"}.`;
  }

  switch (definition.detectionType) {
    case "direct_credential":
      return definition.prefix
        ? `A specific key or token format, starting with “${definition.prefix}”.`
        : "A specific key, token or password format.";
    case "likely_credential":
      return definition.keyNames?.length
        ? `Values that look like secrets, after labels like ${someOf(definition.keyNames)}.`
        : "Values that look like secrets.";
    case "unsafe_handling":
      return "Code that may print or log a secret.";
    case "placeholder_vs_real":
      return "Example values to tell apart from real secrets. Finds nothing on its own.";
    case "model_assessment":
      return "A trained model that rates whether findings look real. Finds nothing on its own.";
    case "model_detection":
      return "A trained model that spots secrets.";
    default:
      return "Not finished yet.";
  }
}
