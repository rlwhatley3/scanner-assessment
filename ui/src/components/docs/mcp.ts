// Reads the MCP server's description from `/api/mcp`: its `initialize` result and its tools, in
// the shapes the MCP spec gives them. `/mcp` itself turns browsers away, so this is read-only.
import { apiUrl } from "../playground/api.ts";

export type JsonSchema = {
  type?: string | string[];
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: unknown[];
  $ref?: string;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
  format?: string;
  minimum?: number;
  maximum?: number;
};

export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

export interface McpTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema: JsonSchema;
  outputSchema?: JsonSchema;
  annotations?: ToolAnnotations;
}

export interface McpDescription {
  initialize: {
    protocolVersion: string;
    capabilities: Record<string, unknown>;
    serverInfo: { name: string; version: string; title?: string };
    instructions?: string;
  };
  tools: McpTool[];
}

export async function describeMcp(): Promise<McpDescription> {
  let response: Response;
  try {
    response = await fetch(apiUrl("/api/mcp"));
  } catch {
    throw new Error("Could not reach the scanner API. Is it running?");
  }
  if (!response.ok) {
    throw new Error(`The scanner API could not describe its MCP server (HTTP ${response.status}).`);
  }
  return (await response.json()) as McpDescription;
}

/** A short type label for a schema, e.g. `integer`, `string[]`, `RuleRecord`, `boolean | null`. */
export function schemaType(schema: JsonSchema): string {
  if (schema.$ref) return schema.$ref.split("/").pop() ?? "object";
  if (schema.enum) return schema.enum.map((value) => JSON.stringify(value)).join(" | ");
  const variants = schema.anyOf ?? schema.oneOf;
  if (variants) return variants.map(schemaType).join(" | ");
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : [];
  if (types.length === 0) return "any";
  return types
    .map((type) => (type === "array" && schema.items ? `${schemaType(schema.items)}[]` : type))
    .join(" | ");
}

/** What a tool's annotations say it does, following the spec's defaults: a tool that isn't
 * read-only is taken to be destructive unless it says otherwise. */
export function toolEffect(
  annotations: ToolAnnotations = {},
): "read-only" | "writes" | "destructive" {
  if (annotations.readOnlyHint) return "read-only";
  return annotations.destructiveHint === false ? "writes" : "destructive";
}
