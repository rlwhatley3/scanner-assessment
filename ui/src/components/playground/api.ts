// Client for the scanner API. The types mirror the server's serialized shapes (camelCase).
// Scan text goes out in the request body only; it is never put in a URL or stored here.

export const MAX_INPUT_BYTES = 1024 * 1024;
export const MAX_FINDINGS = 200;

export type Severity = "high" | "medium" | "low";
export type DetectionType =
  | "direct_credential"
  | "likely_credential"
  | "unsafe_handling"
  /** Marks other findings as likely examples; creates no findings of its own. */
  | "placeholder_vs_real"
  /** A model rates each finding's value as likely real or an example; creates no findings. */
  | "model_assessment"
  /** A model flags spans of the text as secrets. */
  | "model_detection";

export interface Location {
  startByte: number;
  endByte: number;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface MatchDetails {
  ruleName: string;
  detectionType: DetectionType;
  severity: Severity;
  confidence: number;
  placeholderScore: number | null;
  location: Location;
  redactedPreview: string | null;
  whyFlagged: string;
  remediation: string;
  overlapGroup: number | null;
  /** Whether the match sits inside a comment, where examples and dead code usually live. */
  inComment: boolean;
  /** Whether the value passed the rule's checksum; null when the rule has none. */
  checksumValid: boolean | null;
  /** What the rule's value classifier says the value is; null when the rule has none. Missing
   * on findings saved before value classifiers existed. */
  valueClass?: ValueClass | null;
  /** What each model assessment rule concluded about the value. Missing on findings saved
   * before model rules existed. */
  modelAssessments?: ModelAssessment[];
}

/** What a value classifier says a matched value is, with its 0–100 scores. */
export interface ValueClass {
  label: "credential" | "non_secret" | "placeholder";
  credential: number;
  nonSecret: number;
  placeholder: number;
}

/** A model's verdict on a finding's value. It sits beside the rule's scores and never changes
 * them. */
export interface ModelAssessment {
  ruleId: number;
  ruleName: string;
  /** How likely the model rates the value as a real secret, 0–100. */
  score: number;
  verdict: "likely_real" | "likely_example";
}

/** A problem that stops a rule from running or from joining a rule set version. */
export interface RuleError {
  ruleId: number;
  /** The definition field at fault, in snake_case (e.g. `pattern`, `min_entropy`). */
  field: string;
  code: string;
  message: string;
  span: [number, number] | null;
}

export interface RuleWarning {
  ruleId: number;
  field: string;
  code: string;
  message: string;
}

export type Finding =
  | { ruleId: number; kind: "match"; violation: MatchDetails; violationPretty: string }
  | { ruleId: number; kind: "rule_error"; violation: RuleError; violationPretty: string };

export type MatchFinding = Extract<Finding, { kind: "match" }>;

/** A finding as stored and returned by the API. */
export type SavedFinding = Finding & { id: number };

/** A saved match. */
export type SavedMatch = Extract<SavedFinding, { kind: "match" }>;

/** One value found by one rule, marked as known to be safe within one scan session. Later scans
 * in the session don't report it until it expires or is removed. The value and its fingerprint
 * never reach the UI. */
export interface Suppression {
  id: number;
  scanSessionId: number;
  ruleId: number;
  ruleName: string;
  /** The finding it was made from, and that finding's scan. */
  findingId: number;
  scanId: number;
  reason: string;
  expiresAt: string;
  removedAt: string | null;
  status: "active" | "expired" | "removed";
  createdAt: string;
  updatedAt: string;
}

export interface ScanResponse {
  scanId: number;
  scanSessionId: number;
  findings: SavedFinding[];
  /** True when there were more findings than the cap and the rest were not saved. */
  truncated: boolean;
  /** True when at least one rule could not run. */
  partial: boolean;
  /** Matches left out because an active suppression in the session covers their value. */
  suppressedCount: number;
}

export type ChecksumEncoding = "base62" | "base36" | "hex" | "digits";

/** A token read as prefix + covered part + checksum, where the checksum is a CRC32. */
export interface Crc32Checksum {
  algorithm: "crc32";
  encoding: ChecksumEncoding;
  /** Characters at the start the checksum doesn't cover, such as `ghp_`. */
  prefixLength: number;
  /** Characters at the end that hold the checksum. */
  length: number;
}

/** Keep only values that look like a password a person made up, scoring at least `minScore`. */
export interface PasswordShape {
  minScore: number;
}

/** A Microsoft identifiable key: base64 whose last 4 bytes are a Marvin32 hash of the rest. */
export interface Marvin32Checksum {
  algorithm: "marvin32";
  /** The key kind's 8-character seed name, such as `Default0` for Azure Storage. */
  seed: string;
}

/** How a check digit's weighted sum becomes the check. */
export type CheckRule = "complement" | "remainder";

/**
 * An in-house check at the end of a token: the covered part's characters, each worth its
 * position in `alphabet`, times `weights` from the right, summed mod `modulus`.
 */
export interface CheckDigitChecksum {
  algorithm: "check_digit";
  alphabet: string;
  weights: number[];
  modulus: number;
  check: CheckRule;
  prefixLength: number;
  length: number;
}

export type HashFunction = "sha256" | "sha1" | "md5";

/** An in-house check at the end of a token: the first `bytes` bytes of a hash of the covered part. */
export interface HashChecksum {
  algorithm: "hash";
  hash: HashFunction;
  bytes: number;
  encoding: ChecksumEncoding;
  prefixLength: number;
  length: number;
}

/** How a token format's built-in check works, so the engine can test each match offline. */
export type Checksum =
  | Crc32Checksum
  | CheckDigitChecksum
  | HashChecksum
  | Marvin32Checksum
  | {
      algorithm:
        | "luhn"
        | "base58check"
        | "bech32"
        | "bech32m"
        | "bip39"
        | "verhoeff"
        | "mod11"
        | "mod97";
    };

/** Unset fields may be missing or null (the built-in rules are seeded with explicit nulls). */
export interface RuleDefinition {
  name?: string;
  /** Missing means enabled. */
  enabled?: boolean;
  detectionType?: DetectionType;
  severity?: Severity;
  pattern?: string;
  prefix?: string;
  keyNames?: string[];
  minEntropy?: number | null;
  checksum?: Checksum | null;
  passwordShape?: PasswordShape | null;
  remediation?: string;
  /** For model rules: the model, named by the SHA-256 of its file. */
  model?: { id?: string | null; sha256?: string | null } | null;
  /** For model rules: a model score (0–100) at or above this counts as a secret. */
  threshold?: number | null;
  valueClassifier?: ValueClassifier | null;
  /** Fields this UI doesn't edit (e.g. a newer engine's `checksum`) are kept as-is. */
  [other: string]: unknown;
}

/** What a model can be used for: a model rule type, or a rule's value classifier setting. */
export type ModelUse = "model_assessment" | "model_detection" | "value_classifier";

/** A model the API has loaded, which rules name by SHA-256. */
export interface Model {
  id: string;
  sha256: string;
  /** How many token ids the model reads at once. */
  inputLength: number;
  uses: ModelUse[];
}

/** A model as a rule names it. */
export interface ModelRef {
  id?: string;
  sha256: string;
}

/** Runs a model on a rule's matches; values it rates below `minScore` as a credential get lower
 * confidence. */
export interface ValueClassifier {
  model?: { id?: string | null; sha256?: string | null } | null;
  minScore?: number | null;
}

export interface Rule {
  id: number;
  drafting: boolean;
  definition: RuleDefinition;
  versionIds: number[];
  createdAt: string;
  updatedAt: string;
}

export interface RuleCheck {
  errors: RuleError[];
  warnings: RuleWarning[];
}

/** A named line of versions. Names are unique, ignoring case. */
export interface RuleSet {
  id: number;
  name: string;
  description: string;
  /** Archived sets are hidden, can't get new versions, and can't start new scan sessions. */
  archived: boolean;
  versionCount: number;
  /** The newest version that isn't archived. New versions start from it. */
  latestVersionId: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface RuleSetDetail extends RuleSet {
  /** Every version, archived ones included, oldest first. */
  versions: RuleSetVersion[];
}

export interface RuleSetVersion {
  id: number;
  ruleSetId: number;
  ruleSetName: string;
  /** The version's place in its rule set: 1 for the first, and so on. */
  number: number;
  parentId: number | null;
  archived: boolean;
  ruleCount: number;
  scanSessionCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface RuleSetVersionDetail extends RuleSetVersion {
  rules: { ruleId: number; definition: RuleDefinition }[];
}

export interface ScanSession {
  id: number;
  ruleSetVersionId: number;
  ruleSetId: number;
  ruleSetName: string;
  versionNumber: number;
  lastRan: string | null;
  scanCount: number;
  /** Suppressions that apply to the next scan: not removed and not expired. */
  activeSuppressionCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface StoredScan {
  id: number;
  truncated: boolean;
  /** True when at least one rule could not run. */
  partial: boolean;
  /** Matches only; rule errors are counted by `partial`. */
  matchCount: number;
  /** Matches left out because an active suppression covered their value. */
  suppressedCount: number;
  createdAt: string;
  findings: SavedFinding[];
}

export interface ScanSessionDetail extends ScanSession {
  scans: StoredScan[];
}

/** Why a request failed, so the UI can say what the user can do about it. */
export class ApiError extends Error {
  constructor(
    readonly reason: "unreachable" | "rejected" | "unavailable" | "server",
    message: string,
    /** Per-rule problems, when the request failed validation. */
    readonly errors: RuleError[] = [],
  ) {
    super(message);
  }
}

export function apiUrl(path: string): string {
  const baseUrl = new URL(import.meta.env.BASE_URL, window.location.origin);
  return new URL(path.replace(/^\/+/, ""), baseUrl).toString();
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      method,
      headers: body === undefined ? undefined : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    throw new ApiError("unreachable", "Could not reach the scanner API. Is it running?");
  }

  if (response.status === 204) return undefined as T;
  if (response.ok) return (await response.json()) as T;

  // Error bodies are the API's own messages; it never echoes scan text back.
  let detail: { error?: string; errors?: RuleError[] } = {};
  try {
    detail = await response.json();
  } catch {
    // Not JSON (e.g. a proxy error page); fall back to the status below.
  }
  if (response.status >= 500) {
    throw new ApiError("server", `The scanner API failed (HTTP ${response.status}).`);
  }
  throw new ApiError(
    response.status === 404 ? "unavailable" : "rejected",
    detail.error || `The scanner API rejected the request (HTTP ${response.status}).`,
    detail.errors ?? [],
  );
}

export async function checkHealth(signal?: AbortSignal): Promise<boolean> {
  try {
    const response = await fetch(apiUrl("/api/health"), { signal });
    return response.ok;
  } catch (error) {
    if (signal?.aborted) throw error;
    return false;
  }
}

export const listModels = () => request<Model[]>("GET", "/api/models");
export const listRules = () => request<Rule[]>("GET", "/api/rules");
export const createRule = (definition: RuleDefinition = {}) =>
  request<Rule>("POST", "/api/rules", { definition });
export const saveRule = (id: number, definition: RuleDefinition) =>
  request<Rule>("PUT", `/api/rules/${id}`, { definition });
export const deleteRule = (id: number) => request<void>("DELETE", `/api/rules/${id}`);
export const checkRule = (id: number, definition: RuleDefinition, signal?: AbortSignal) =>
  request<RuleCheck>("POST", `/api/rules/${id}/check`, { definition }, signal);

/** What one rule finds in sample text. Nothing is saved, so findings have no ids. */
export interface TryRuleResponse {
  truncated: boolean;
  findings: Finding[];
}

/** Whether one example value passes a checksum, and where its parts start. */
export interface TryChecksumResponse {
  valid: boolean;
  layout: { coveredStart: number; checksumStart: number } | null;
}

/** Checks one example value against a checksum setup. Nothing is stored. */
export const tryChecksum = (checksum: Checksum, value: string, signal?: AbortSignal) =>
  request<TryChecksumResponse>("POST", "/api/checksums/try", { checksum, value }, signal);

/** Runs a rule definition, saved or not, on sample text. The text goes in the body only. */
export const tryRule = (
  id: number,
  definition: RuleDefinition,
  text: string,
  signal?: AbortSignal,
) => request<TryRuleResponse>("POST", `/api/rules/${id}/try`, { definition, text }, signal);

export const listRuleSets = (includeArchived = false) =>
  request<RuleSet[]>("GET", `/api/rule-sets${includeArchived ? "?includeArchived=true" : ""}`);
export const getRuleSet = (id: number) => request<RuleSetDetail>("GET", `/api/rule-sets/${id}`);
export const createRuleSet = (body: {
  name: string;
  description: string;
  fromVersionId: number | null;
}) => request<RuleSetDetail>("POST", "/api/rule-sets", body);
export const updateRuleSet = (
  id: number,
  changes: { name?: string; description?: string; archived?: boolean },
) => request<RuleSet>("PATCH", `/api/rule-sets/${id}`, changes);

export function listVersions(options: { ruleSetId?: number; includeArchived?: boolean } = {}) {
  const query = new URLSearchParams();
  if (options.ruleSetId !== undefined) query.set("ruleSetId", String(options.ruleSetId));
  if (options.includeArchived) query.set("includeArchived", "true");
  const suffix = query.size > 0 ? `?${query}` : "";
  return request<RuleSetVersion[]>("GET", `/api/rule-set-versions${suffix}`);
}
export const getVersion = (id: number) =>
  request<RuleSetVersionDetail>("GET", `/api/rule-set-versions/${id}`);
export const createVersion = (ruleSetId: number, ruleIds: number[], parentId: number | null) =>
  request<RuleSetVersionDetail>("POST", "/api/rule-set-versions", {
    ruleSetId,
    ruleIds,
    parentId,
  });
export const setVersionArchived = (id: number, archived: boolean) =>
  request<RuleSetVersion>("PATCH", `/api/rule-set-versions/${id}`, { archived });

export const listSessions = () => request<ScanSession[]>("GET", "/api/scan-sessions");
export const getSession = (id: number) =>
  request<ScanSessionDetail>("GET", `/api/scan-sessions/${id}`);
export const createSession = (ruleSetVersionId: number) =>
  request<ScanSession>("POST", "/api/scan-sessions", {
    ruleSetVersionId,
  });

export const runScan = (sessionId: number, text: string, signal: AbortSignal) =>
  request<ScanResponse>("POST", `/api/scan-sessions/${sessionId}/scans`, { text }, signal);
export const getScan = (sessionId: number, scanId: number) =>
  request<ScanResponse>("GET", `/api/scan-sessions/${sessionId}/scans/${scanId}`);

export const listSuppressions = (sessionId: number) =>
  request<Suppression[]>("GET", `/api/scan-sessions/${sessionId}/suppressions`);
export const createSuppression = (
  sessionId: number,
  body: { findingId: number; reason: string; expiresAt: string },
) => request<Suppression>("POST", `/api/scan-sessions/${sessionId}/suppressions`, body);
export const removeSuppression = (sessionId: number, suppressionId: number) =>
  request<Suppression>("DELETE", `/api/scan-sessions/${sessionId}/suppressions/${suppressionId}`);

/** How a version is named in the UI, e.g. "Payments v2". */
export function versionLabel(version: { ruleSetName: string; number: number }): string {
  return `${version.ruleSetName} v${version.number}`;
}

/** A rule's display name, for rules whose definition has no name yet. */
export function ruleName(definition: RuleDefinition, id: number): string {
  return definition.name?.trim() || `Untitled rule ${id}`;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
