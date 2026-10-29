import { Fragment } from "react";
import { useLoad } from "../playground/useLoad.ts";
import { describeMcp, type JsonSchema, type McpTool, schemaType, toolEffect } from "./mcp.ts";
import "./style.css";

const EFFECT_LABELS = {
  "read-only": "Read-only",
  writes: "Writes",
  destructive: "Destructive",
} as const;

/** Lets a long tool name wrap after its underscores rather than mid-word. */
function breakAtUnderscores(name: string) {
  return name.split("_").map((part, index) => (
    // biome-ignore lint/suspicious/noArrayIndexKey: the parts of a fixed name never reorder.
    <Fragment key={index}>
      {index > 0 && (
        <>
          _<wbr />
        </>
      )}
      {part}
    </Fragment>
  ));
}

function ParameterTable({ schema }: { schema: JsonSchema }) {
  const entries = Object.entries(schema.properties ?? {});
  if (entries.length === 0) return <p className="mcp-none">No parameters.</p>;
  const required = new Set(schema.required ?? []);

  return (
    <table className="mcp-params">
      <thead>
        <tr>
          <th scope="col">Name</th>
          <th scope="col">Type</th>
          <th scope="col">Description</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([name, property]) => (
          <tr key={name}>
            <td>
              <code>{name}</code>
              {required.has(name) && <span className="mcp-required">required</span>}
            </td>
            <td>
              <code className="mcp-type">{schemaType(property)}</code>
            </td>
            <td className="mcp-text">{property.description}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function RawSchema({ label, schema }: { label: string; schema: JsonSchema }) {
  return (
    <details className="mcp-raw">
      <summary>{label}</summary>
      <pre>{JSON.stringify(schema, null, 2)}</pre>
    </details>
  );
}

function ToolSection({ tool }: { tool: McpTool }) {
  const effect = toolEffect(tool.annotations);

  return (
    <section
      className="mcp-tool"
      id={`tool-${tool.name}`}
      aria-labelledby={`tool-${tool.name}-name`}
    >
      <header className="mcp-tool-header">
        <h2 id={`tool-${tool.name}-name`}>
          <code>{tool.name}</code>
        </h2>
        <span className={`mcp-badge mcp-badge-${effect}`}>{EFFECT_LABELS[effect]}</span>
        {tool.annotations?.idempotentHint && <span className="mcp-badge">Idempotent</span>}
      </header>
      {tool.title && <p className="mcp-title">{tool.title}</p>}
      {tool.description && <p className="mcp-text">{tool.description}</p>}

      <h3>Parameters</h3>
      <ParameterTable schema={tool.inputSchema} />
      <RawSchema label="Input schema" schema={tool.inputSchema} />
      {tool.outputSchema && <RawSchema label="Output schema" schema={tool.outputSchema} />}
    </section>
  );
}

export default function McpDocsView() {
  const { data, error, loading } = useLoad(describeMcp, []);

  if (!data) {
    return (
      <main className="mcp-docs mcp-status">
        <p className={error ? "mcp-error" : undefined}>
          {loading ? "Loading the MCP server's tools…" : error}
        </p>
      </main>
    );
  }

  const { initialize, tools } = data;
  return (
    <main className="mcp-docs">
      <nav className="mcp-index" aria-label="MCP tools">
        <p className="mcp-index-heading">Tools</p>
        <ul>
          {tools.map((tool) => (
            <li key={tool.name}>
              <a href={`#tool-${tool.name}`}>{breakAtUnderscores(tool.name)}</a>
            </li>
          ))}
        </ul>
      </nav>

      <div className="mcp-content">
        <header className="mcp-intro">
          <h1>
            {initialize.serverInfo.title ?? initialize.serverInfo.name}
            <span className="mcp-version">{initialize.serverInfo.version}</span>
          </h1>
          <dl className="mcp-facts">
            <div>
              <dt>Endpoint</dt>
              <dd>
                <code>/mcp</code> on the API, streamable HTTP
              </dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>
                <code>{initialize.protocolVersion}</code>
              </dd>
            </div>
            <div>
              <dt>Capabilities</dt>
              <dd>{Object.keys(initialize.capabilities).join(", ")}</dd>
            </div>
          </dl>
          <p>
            Every tool below is listed as <code>tools/list</code> returns it. To add the server to
            Claude Code while the stack is running:
          </p>
          <pre className="mcp-command">
            claude mcp add --transport http secrets-scanner http://127.0.0.1:3001/mcp
          </pre>
          <p className="mcp-note">
            It only accepts loopback connections and rejects requests from web pages, so this page
            documents the tools but can't call them.
          </p>
          {initialize.instructions && (
            <>
              <h2>Instructions</h2>
              <p className="mcp-text">{initialize.instructions}</p>
            </>
          )}
        </header>

        {tools.map((tool) => (
          <ToolSection key={tool.name} tool={tool} />
        ))}
      </div>
    </main>
  );
}
