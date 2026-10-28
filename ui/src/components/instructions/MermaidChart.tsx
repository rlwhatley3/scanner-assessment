import { type MermaidConfig, mermaid } from "@streamdown/mermaid";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { CustomRendererProps } from "streamdown";

type ViewBox = { x: number; y: number; width: number; height: number };
type Anchor = { x: number; y: number };
type DragState = { clientX: number; clientY: number; viewBox: ViewBox };

export const mermaidConfig: MermaidConfig = {
  theme: "neutral",
  securityLevel: "strict",
  suppressErrorRendering: false,
  fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
  fontSize: 20,
  flowchart: { useMaxWidth: true, htmlLabels: false, curve: "linear" },
  sequence: { useMaxWidth: true },
};

const MIN_ZOOM = 1;
const MAX_ZOOM = 2.5;

export default function MermaidChart({ code }: CustomRendererProps) {
  const instanceId = useId().replaceAll(":", "");
  const viewportRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<DragState | null>(null);
  const baseViewBoxRef = useRef<ViewBox | null>(null);
  const [svg, setSvg] = useState("");
  const [viewBox, setViewBox] = useState<ViewBox | null>(null);
  const [error, setError] = useState("");
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    let active = true;
    const renderId = `submission-mermaid-${instanceId}`;
    const renderer = mermaid.getMermaid(mermaidConfig);

    void renderer
      .render(renderId, code)
      .then(({ svg: renderedSvg }) => {
        if (!active) return;
        const match = renderedSvg.match(/viewBox=["']([^"']+)["']/i);
        const values = match?.[1]
          .trim()
          .split(/[\s,]+/)
          .map(Number);
        if (values?.length !== 4 || values.some((value) => !Number.isFinite(value))) {
          throw new Error("The diagram did not produce a valid SVG viewBox.");
        }
        const [x, y, width, height] = values;
        if (width <= 0 || height <= 0) throw new Error("The diagram has invalid dimensions.");
        const initial = { x, y, width, height };
        baseViewBoxRef.current = initial;
        setViewBox(initial);
        setSvg(renderedSvg);
        setError("");
      })
      .catch((renderError: unknown) => {
        if (active) {
          setError(
            renderError instanceof Error ? renderError.message : "Unable to render diagram.",
          );
        }
      });

    return () => {
      active = false;
    };
  }, [code, instanceId]);

  const zoomAt = useCallback((factor: number, anchor: Anchor = { x: 0.5, y: 0.5 }) => {
    const base = baseViewBoxRef.current;
    if (!base) return;

    setViewBox((current) => {
      if (!current) return current;
      const zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, (base.width / current.width) * factor));
      const width = base.width / zoom;
      const height = base.height / zoom;
      const centerX = current.x + current.width * anchor.x;
      const centerY = current.y + current.height * anchor.y;
      return clampViewBox(
        { x: centerX - width * anchor.x, y: centerY - height * anchor.y, width, height },
        base,
      );
    });
  }, []);

  useEffect(() => {
    const viewport = viewportRef.current;
    if (!viewport) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const rect = viewport.getBoundingClientRect();
      zoomAt(event.deltaY < 0 ? 1.15 : 1 / 1.15, {
        x: Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width)),
        y: Math.min(1, Math.max(0, (event.clientY - rect.top) / rect.height)),
      });
    };
    viewport.addEventListener("wheel", onWheel, { passive: false });
    return () => viewport.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  const zoom = baseViewBoxRef.current && viewBox ? baseViewBoxRef.current.width / viewBox.width : 1;
  const displayedSvg = svg && viewBox ? withViewBox(svg, viewBox) : "";

  function onPointerDown(event: React.PointerEvent<HTMLDivElement>) {
    if (event.button !== 0 || !viewBox) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = { clientX: event.clientX, clientY: event.clientY, viewBox };
    setIsDragging(true);
  }

  function onPointerMove(event: React.PointerEvent<HTMLDivElement>) {
    const drag = dragRef.current;
    const base = baseViewBoxRef.current;
    const viewport = viewportRef.current;
    if (!drag || !base || !viewport) return;
    const rect = viewport.getBoundingClientRect();
    const next = {
      ...drag.viewBox,
      x: drag.viewBox.x - ((event.clientX - drag.clientX) / rect.width) * drag.viewBox.width,
      y: drag.viewBox.y - ((event.clientY - drag.clientY) / rect.height) * drag.viewBox.height,
    };
    setViewBox(clampViewBox(next, base));
  }

  function endDrag(event: React.PointerEvent<HTMLDivElement>) {
    dragRef.current = null;
    setIsDragging(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }

  return (
    <section className="submission-mermaid-chart" aria-label="Mermaid diagram">
      <header className="submission-mermaid-toolbar">
        <span className="submission-mermaid-label">Mermaid</span>
        <div
          className="submission-mermaid-controls"
          role="toolbar"
          aria-label="Diagram zoom controls"
        >
          <button
            type="button"
            aria-label="Zoom out"
            title="Zoom out"
            disabled={zoom <= MIN_ZOOM}
            onClick={() => zoomAt(1 / 1.2)}
          >
            −
          </button>
          <span aria-live="polite">{Math.round(zoom * 100)}%</span>
          <button
            type="button"
            aria-label="Zoom in"
            title="Zoom in"
            disabled={zoom >= MAX_ZOOM}
            onClick={() => zoomAt(1.2)}
          >
            +
          </button>
          <button
            type="button"
            className="reset-zoom"
            aria-label="Reset zoom"
            title="Reset zoom"
            disabled={zoom === MIN_ZOOM}
            onClick={() => {
              const base = baseViewBoxRef.current;
              if (base) setViewBox(base);
            }}
          >
            Reset
          </button>
        </div>
      </header>
      <section
        className={`submission-mermaid-viewport${isDragging ? " is-dragging" : ""}`}
        ref={viewportRef}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        aria-label="Diagram canvas. Scroll to zoom; drag to pan."
      >
        {error ? (
          <p className="submission-mermaid-error" role="alert">
            Mermaid could not render this diagram: {error}
          </p>
        ) : displayedSvg ? (
          <div
            className="submission-mermaid-svg"
            // biome-ignore lint/security/noDangerouslySetInnerHtml: Mermaid generates this SVG with strict security mode; Markdown HTML is never inserted.
            dangerouslySetInnerHTML={{ __html: displayedSvg }}
          />
        ) : (
          <p className="submission-mermaid-loading">Rendering diagram…</p>
        )}
      </section>
      <p className="submission-mermaid-hint">Scroll to zoom · Drag to pan</p>
    </section>
  );
}

function clampViewBox(view: ViewBox, base: ViewBox): ViewBox {
  const minWidth = base.width / MAX_ZOOM;
  const minHeight = base.height / MAX_ZOOM;
  const width = Math.min(base.width, Math.max(minWidth, view.width));
  const height = Math.min(base.height, Math.max(minHeight, view.height));
  return {
    x: Math.min(base.x + base.width - width, Math.max(base.x, view.x)),
    y: Math.min(base.y + base.height - height, Math.max(base.y, view.y)),
    width,
    height,
  };
}

function withViewBox(svg: string, view: ViewBox) {
  const value = `${view.x} ${view.y} ${view.width} ${view.height}`;
  return svg.replace(/<svg\b([^>]*)>/i, (_match, attributes: string) => {
    const cleaned = attributes
      .replace(/\s(?:width|height|style|viewBox)=(["'])[^"']*\1/gi, "")
      .replace(/\s+$/, "");
    return `<svg${cleaned} viewBox="${value}" preserveAspectRatio="xMidYMid meet" style="display:block;width:100%;height:100%">`;
  });
}

export const mermaidRenderer = { language: "mermaid", component: MermaidChart };
