import type { ComponentProps } from "react";
import { Link } from "react-router-dom";

function MarkdownLink({ href, className, target, ...props }: ComponentProps<"a">) {
  if (href?.startsWith("/") && !href.startsWith("//")) {
    return (
      <Link
        to={href}
        target="_self"
        className={["internal-link", className].filter(Boolean).join(" ")}
        {...props}
      />
    );
  }

  return <a href={href} className={className} target={target} {...props} />;
}

export function slugifyHeading(value: string) {
  return value
    .toLowerCase()
    .replace(/[`*_~]/g, "")
    .replace(/[^\p{L}\p{N}\s-]/gu, "")
    .trim()
    .replace(/\s+/g, "-");
}

export type MarkdownHeadingEntry = { level: 2 | 3; title: string; id: string };

export function getMarkdownHeadings(markdown: string): MarkdownHeadingEntry[] {
  const usedIds = new Map<string, number>();
  let inFence = false;
  return markdown.split("\n").flatMap((line) => {
    if (/^\s*```/.test(line) || /^\s*~~~/.test(line)) {
      inFence = !inFence;
      return [];
    }
    const match = !inFence && line.match(/^#{2,3}\s+(.+?)\s*#*\s*$/);
    if (!match) return [];
    const title = match[1].replace(/`([^`]+)`/g, "$1").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
    const baseId = slugifyHeading(title);
    const count = usedIds.get(baseId) ?? 0;
    usedIds.set(baseId, count + 1);
    return [
      {
        level: line.match(/^###/) ? (3 as const) : (2 as const),
        title,
        id: count ? `${baseId}-${count}` : baseId,
      },
    ];
  });
}

export function createMarkdownComponents() {
  return { a: MarkdownLink };
}
