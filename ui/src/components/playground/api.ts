// Client for the scanner API. The types mirror the server's serialized shapes (snake_case),
// except rule definitions, which are stored in the rule form's camelCase.
// Scan text goes out in the request body only; it is never put in a URL or stored here.

export const MAX_INPUT_BYTES = 1024 * 1024;
export const MAX_FINDINGS = 200;

export type Severity = "high" | "medium" | "low";
export type DetectionType = "direct_credential" | "likely_credential" | "unsafe_handling";

export interface Location {
  start_byte: number;
  end_byte: number;
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

export interface MatchDetails {
  rule_name: string;
  detection_type: DetectionType;
  severity: Severity;
  confidence: number;
  placeholder_score: number | null;
  location: Location;
  redacted_preview: string | null;
  why_flagged: string;
  remediation: string;
  overlap_group: number | null;
}

/** A problem that stops a rule from running or from joining a rule set version. */
export interface RuleError {
  rule_id: number;
  /** The definition field at fault, in snake_case (e.g. `pattern`, `min_entropy`). */
  field: string;
  code: string;
  message: string;
  span: [number, number] | null;
}

export interface RuleWarning {
  rule_id: number;
  field: string;
  code: string;
  message: string;
}

export type Finding =
  | { rule_id: number; kind: "match"; violation: MatchDetails; violation_pretty: string }
  | { rule_id: number; kind: "rule_error"; violation: RuleError; violation_pretty: string };

export type MatchFinding = Extract<Finding, { kind: "match" }>;

export interface ScanResponse {
  scan_id: number;
  findings: Finding[];
  truncated: boolean;
}

export interface RuleDefinition {
  name?: string;
  /** Missing means enabled. */
  enabled?: boolean;
  detectionType?: DetectionType;
  severity?: Severity;
  pattern?: string;
  prefix?: string;
  keyNames?: string[];
  minEntropy?: number;
  remediation?: string;
}

export interface Rule {
  id: number;
  drafting: boolean;
  definition: RuleDefinition;
  version_ids: number[];
  created_at: string;
  updated_at: string;
}

export interface RuleCheck {
  errors: RuleError[];
  warnings: RuleWarning[];
}

export interface RuleSetVersion {
  id: number;
  parent_id: number | null;
  archived: boolean;
  rule_count: number;
  scan_session_count: number;
  created_at: string;
  updated_at: string;
}

export interface RuleSetVersionDetail extends RuleSetVersion {
  rules: { rule_id: number; definition: RuleDefinition }[];
}

export interface ScanSession {
  id: number;
  rule_set_version_id: number;
  last_ran: string | null;
  scan_count: number;
  created_at: string;
  updated_at: string;
}

export interface StoredScan {
  id: number;
  truncated: boolean;
  created_at: string;
  findings: (Finding & { id: number })[];
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
  let detail: { message?: string; errors?: RuleError[] } = {};
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
    detail.message || `The scanner API rejected the request (HTTP ${response.status}).`,
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

export const listVersions = (includeArchived = false) =>
  request<RuleSetVersion[]>(
    "GET",
    `/api/rule-set-versions${includeArchived ? "?include_archived=true" : ""}`,
  );
export const getVersion = (id: number) =>
  request<RuleSetVersionDetail>("GET", `/api/rule-set-versions/${id}`);
export const createVersion = (ruleIds: number[], parentId: number | null) =>
  request<RuleSetVersionDetail>("POST", "/api/rule-set-versions", {
    rule_ids: ruleIds,
    parent_id: parentId,
  });
export const setVersionArchived = (id: number, archived: boolean) =>
  request<RuleSetVersion>("PATCH", `/api/rule-set-versions/${id}`, { archived });

export const listSessions = () => request<ScanSession[]>("GET", "/api/scan-sessions");
export const getSession = (id: number) =>
  request<ScanSessionDetail>("GET", `/api/scan-sessions/${id}`);
export const createSession = (ruleSetVersionId: number) =>
  request<ScanSessionDetail>("POST", "/api/scan-sessions", {
    rule_set_version_id: ruleSetVersionId,
  });

export async function runScan(
  sessionId: number,
  text: string,
  signal: AbortSignal,
): Promise<ScanResponse> {
  try {
    return await request<ScanResponse>(
      "POST",
      `/api/scan-sessions/${sessionId}/scans`,
      { text },
      signal,
    );
  } catch (error) {
    if (error instanceof ApiError && error.reason === "unavailable") {
      throw new ApiError("unavailable", "The scan endpoint is not available on this API yet.");
    }
    throw error;
  }
}

/** A rule's display name, for rules whose definition has no name yet. */
export function ruleName(definition: RuleDefinition, id: number): string {
  return definition.name?.trim() || `Untitled rule ${id}`;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
