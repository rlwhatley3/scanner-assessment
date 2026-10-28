import { lazy, Suspense } from "react";
import { useSearchParams } from "react-router-dom";
import deliverables from "../../../docs/deliverables.md?raw";
import overview from "../../../docs/overview.md?raw";
import phase1 from "../../../docs/phase-1.md?raw";
import phase2 from "../../../docs/phase-2.md?raw";
import phase3 from "../../../docs/phase-3.md?raw";
import "./style.css";

const MarkdownRenderer = lazy(() => import("./MarkdownRenderer"));

const phases = [
  { id: "phase-1", label: "Phase 1", title: "Whiteboard", markdown: phase1 },
  {
    id: "phase-2",
    label: "Phase 2",
    title: "Implementation",
    markdown: phase2,
  },
  { id: "phase-3", label: "Phase 3", title: "New feedback", markdown: phase3 },
] as const;

type PhaseId = (typeof phases)[number]["id"];

export default function InstructionsView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const currentPhase = phases.find((phase) => phase.id === searchParams.get("phase")) ?? phases[0];
  const activePhase: PhaseId = currentPhase.id;

  return (
    <Suspense
      fallback={<div className="instructions-loading">Loading instructions - one moment</div>}
    >
      <main
        id="instructions-panel"
        className="instructions-layout"
        aria-label="Assessment instructions"
      >
        <div className="instructions-columns">
          <section className="panel instructions-intro">
            <MarkdownRenderer className="markdown-content overview-content">
              {overview}
            </MarkdownRenderer>
            <section className="phase-workspace">
              <div className="phase-tabs" role="tablist" aria-label="Assessment phases">
                {phases.map((phase, index) => (
                  <button
                    type="button"
                    key={phase.id}
                    id={`${phase.id}-tab`}
                    aria-controls={`${phase.id}-panel`}
                    aria-selected={activePhase === phase.id}
                    role="tab"
                    className="phase-tab"
                    onClick={() =>
                      setSearchParams((current) => {
                        const next = new URLSearchParams(current);
                        next.set("phase", phase.id);
                        return next;
                      })
                    }
                  >
                    <span className="phase-tab-number">0{index + 1}</span>
                    <span className="phase-tab-label">{phase.label}</span>
                    <small>{phase.title}</small>
                  </button>
                ))}
              </div>

              <section
                id={`${activePhase}-panel`}
                aria-labelledby={`${activePhase}-tab`}
                role="tabpanel"
                className="panel"
              >
                <MarkdownRenderer className="markdown-content">
                  {currentPhase.markdown}
                </MarkdownRenderer>
              </section>
            </section>
          </section>
          <aside className="instructions-sidebar" aria-label="Assessment checklist">
            <section
              className="panel deliverables-card"
              aria-label="Submission and walkthrough details"
            >
              <section
                className="assessment-content-panel"
                aria-label="Submission and walkthrough details"
                // biome-ignore lint/a11y/noNoninteractiveTabindex: The named overflow region must be focusable for keyboard scrolling.
                tabIndex={0}
              >
                <MarkdownRenderer className="markdown-content deliverables-copy">
                  {deliverables}
                </MarkdownRenderer>
              </section>
            </section>
          </aside>
        </div>
      </main>
    </Suspense>
  );
}
