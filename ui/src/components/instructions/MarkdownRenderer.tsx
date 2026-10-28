import { code } from "@streamdown/code";
import { mermaid } from "@streamdown/mermaid";
import { Streamdown } from "streamdown";
import { createMarkdownComponents } from "./MarkdownComponents";
import { mermaidConfig, mermaidRenderer } from "./MermaidChart";

type Props = {
  children: string;
  className?: string;
};

const plugins = { code, mermaid, renderers: [mermaidRenderer] };
const components = createMarkdownComponents();
const controls = { code: false, mermaid: false, table: false };
const mermaidStart =
  /^(?:flowchart\s+(?:TB|TD|BT|RL|LR)\b|graph\s+(?:TB|TD|BT|RL|LR)\b|sequenceDiagram\b|stateDiagram(?:-v2)?\b|classDiagram\b|erDiagram\b|gantt\b|journey\b|mindmap\b|timeline\b)/i;

function normalizeMermaidFences(markdown: string) {
  const lines = markdown.split("\n");
  let insideFence = false;
  return lines
    .map((line, index) => {
      const opening = line.match(/^(\s*)(`{3,}|~{3,})(.*)$/);
      if (!opening) return line;
      if (insideFence) {
        insideFence = false;
        return line;
      }
      insideFence = !insideFence;

      const [, indent, fence, info] = opening;
      const language = info.trim();
      if (/^mermaid(?:\s|$)/i.test(language)) {
        return `${indent}${fence}mermaid`;
      }
      if (!language && mermaidStart.test(lines[index + 1]?.trim() ?? "")) {
        return `${indent}${fence}mermaid`;
      }
      return line;
    })
    .join("\n");
}

export default function MarkdownRenderer({ children, className }: Props) {
  return (
    <Streamdown
      mode="static"
      className={className}
      components={components}
      plugins={plugins}
      controls={controls}
      tableMaxHeight={0}
      mermaid={{ config: mermaidConfig }}
    >
      {normalizeMermaidFences(children)}
    </Streamdown>
  );
}
