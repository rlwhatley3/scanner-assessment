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
  | "placeholder_vs_real";

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

export interface ScanResponse {
  scanId: number;
  scanSessionId: number;
  findings: SavedFinding[];
  /** True when there were more findings than the cap and the rest were not saved. */
  truncated: boolean;
  /** True when at least one rule could not run. */
  partial: boolean;
}

export type ChecksumEncoding = "base62" | "base36" | "hex";

/** A token read as prefix + covered part + checksum, where the checksum is a CRC32. */
export interface Crc32Checksum {
  algorithm: "crc32";
  encoding: ChecksumEncoding;
  /** Characters at the start the checksum doesn't cover, such as `ghp_`. */
  prefixLength: number;
  /** Characters at the end that hold the checksum. */
  length: number;
}

/** How a token format's built-in check works, so the engine can test each match offline. */
export type Checksum = Crc32Checksum | { algorithm: "luhn" } | { algorithm: "base58check" };

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
  remediation?: string;
  /** Fields this UI doesn't edit (e.g. a newer engine's `checksum`) are kept as-is. */
  [other: string]: unknown;
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

export const listRules = () => request<Rule[]>("GET", "/api/rules");
export const createRule = (definition: RuleDefinition = {}) =>
  request<Rule>("POST", "/api/rules", { definition });
export const saveRule = (id: number, definition: RuleDefinition) =>
  request<Rule>("PUT", `/api/rules/${id}`, { definition });
export const deleteRule = (id: number) => request<void>("DELETE", `/api/rules/${id}`);
export const checkRule = (id: number, definition: RuleDefinition, signal?: AbortSignal) =>
  request<RuleCheck>("POST", `/api/rules/${id}/check`, { definition }, signal);

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
