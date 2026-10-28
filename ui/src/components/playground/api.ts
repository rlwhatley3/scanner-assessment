// Client for the scanner API. The types mirror the engine's serialized shapes (snake_case).
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

export interface RuleError {
  rule_id: number;
  field: string;
  code: string;
  message: string;
  span: [number, number] | null;
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

/** Why a request failed, so the UI can say what the user can do about it. */
export class ApiError extends Error {
  constructor(
    readonly reason: "unreachable" | "rejected" | "unavailable" | "server",
    message: string,
  ) {
    super(message);
  }
}

export function apiUrl(path: string): string {
  const baseUrl = new URL(import.meta.env.BASE_URL, window.location.origin);
  return new URL(path.replace(/^\/+/, ""), baseUrl).toString();
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

export async function runScan(text: string, signal: AbortSignal): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(apiUrl("/api/scans"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      signal,
    });
  } catch (error) {
    if (signal.aborted) throw error;
    throw new ApiError("unreachable", "Could not reach the scanner API. Is it running?");
  }

  if (response.ok) return (await response.json()) as ScanResponse;

  // The API's error bodies are its own messages; it never echoes the scan text back.
  const detail = (await response.text()).trim();
  if (response.status === 404) {
    throw new ApiError("unavailable", "The scan endpoint is not available on this API yet.");
  }
  if (response.status >= 500) {
    throw new ApiError("server", `The scanner API failed (HTTP ${response.status}).`);
  }
  throw new ApiError(
    "rejected",
    detail || `The scanner API rejected the request (HTTP ${response.status}).`,
  );
}
