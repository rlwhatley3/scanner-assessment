// The simple rule editor describes what a secret looks like in plain terms and writes the
// pattern for it. These functions turn that description into rule fields and back.

import type { DetectionType } from "../api.ts";

export const CHARSETS = {
  alphanumeric: { label: "letters and numbers", chars: "A-Za-z0-9" },
  token: { label: "letters, numbers, - and _", chars: "A-Za-z0-9_-" },
  hex: { label: "hex digits (0–9, a–f)", chars: "0-9a-fA-F" },
  digits: { label: "numbers only", chars: "0-9" },
} as const;

export type Charset = keyof typeof CHARSETS;

export type Shape =
  /** A fixed start, then a run of characters, e.g. `acme_` plus 24 letters and numbers. */
  | { kind: "prefix"; prefix: string; length: string; charset: Charset }
  /** A value assigned to a label, e.g. `password = …` or `token: …`. */
  | { kind: "label"; labels: string }
  /** Anything else: a hand-written pattern, or a rule that doesn't use one. */
  | { kind: "custom" };

/** The fields a shape sets on a rule. */
export interface ShapeFields {
  pattern: string;
  prefix: string;
  keyNames: string;
  detectionType: DetectionType;
}

/** Matches a name, then `=` or `:`, then a value of at least 8 characters. Key names pick which
 * names count. The same pattern as the built-in "Secret-looking assignment" rule. */
export const LABEL_PATTERN =
  // biome-ignore lint/suspicious/noTemplateCurlyInString: `${}` are regex characters here.
  "(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)[\"']?\\s*[:=]\\s*[\"']?(?P<value>[^\\s\"'`,;${}()]{8,})";

export const NEW_PREFIX_SHAPE: Shape = {
  kind: "prefix",
  prefix: "",
  length: "24",
  charset: "alphanumeric",
};

function escapeRegex(text: string): string {
  return text.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
}

function unescapeRegex(text: string): string | null {
  // Only escaped punctuation and plain characters; anything else is a real regex.
  if (/(^|[^\\])[\^$.*+?()[\]{}|]/.test(text)) return null;
  return text.replace(/\\(.)/g, "$1");
}

/** The rule fields for a prefix or label shape; null for a custom one. */
export function shapeFields(shape: Shape): ShapeFields | null {
  if (shape.kind === "label") {
    return {
      pattern: LABEL_PATTERN,
      prefix: "",
      keyNames: shape.labels,
      detectionType: "likely_credential",
    };
  }
  if (shape.kind === "custom") return null;
  const { chars } = CHARSETS[shape.charset];
  const length = shape.length.trim() || "1";
  // \b only works next to a letter, digit, or underscore.
  const start = /^\w/.test(shape.prefix) || shape.prefix === "" ? "\\b" : "";
  return {
    pattern: `${start}(?P<value>${escapeRegex(shape.prefix)}[${chars}]{${length}})(?:[^${chars}]|$)`,
    prefix: shape.prefix,
    keyNames: "",
    detectionType: "direct_credential",
  };
}

/** Reads a rule's fields back as a shape, when they are what `shapeFields` writes. */
export function shapeOf(fields: {
  pattern: string;
  keyNames: string;
  detectionType: DetectionType | "";
}): Shape {
  if (fields.pattern === "") return NEW_PREFIX_SHAPE;
  if (fields.pattern === LABEL_PATTERN) return { kind: "label", labels: fields.keyNames };
  const match = /^(?:\\b)?\(\?P<value>(.*)\[([^\]]+)\]\{(\d+)\}\)\(\?:\[\^([^\]]+)\]\|\$\)$/.exec(
    fields.pattern,
  );
  if (match && fields.detectionType === "direct_credential") {
    const [, escaped, chars, length, after] = match;
    const charset = (Object.keys(CHARSETS) as Charset[]).find(
      (key) => CHARSETS[key].chars === chars && chars === after,
    );
    const prefix = unescapeRegex(escaped);
    if (charset && prefix !== null) return { kind: "prefix", prefix, length, charset };
  }
  return { kind: "custom" };
}
