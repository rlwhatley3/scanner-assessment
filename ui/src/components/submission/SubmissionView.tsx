import { lazy, Suspense, useEffect, useRef } from "react";
import markdown from "../../../../SUBMISSION.md?raw";
import { getMarkdownHeadings } from "../instructions/MarkdownComponents";
import "./style.css";

const MarkdownRenderer = lazy(() => import("../instructions/MarkdownRenderer"));
const headings = getMarkdownHeadings(markdown);

export default function SubmissionView() {
  const markdownRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const root = markdownRef.current;
    if (!root) return;

    let initialHashPending = Boolean(window.location.hash);
    const assignHeadingIds = () => {
      const renderedHeadings = root.querySelectorAll<HTMLElement>("h2, h3");
      renderedHeadings.forEach((element, index) => {
        const entry = headings[index];
        if (entry) element.id = entry.id;
      });

      if (initialHashPending) {
        const id = decodeHash(window.location.hash);
        if (id && scrollToHeading(root, id, "auto")) initialHashPending = false;
      }
    };

    assignHeadingIds();
    const observer = new MutationObserver(assignHeadingIds);
    observer.observe(root, { childList: true, subtree: true });
    const handleHistoryNavigation = () => {
      const id = decodeHash(window.location.hash);
      if (id) scrollToHeading(root, id, "smooth");
    };
    window.addEventListener("popstate", handleHistoryNavigation);

    return () => {
      observer.disconnect();
      window.removeEventListener("popstate", handleHistoryNavigation);
    };
  }, []);

  function navigateToHeading(id: string) {
    const root = markdownRef.current;
    if (!root) return false;

    root.querySelectorAll<HTMLElement>("h2, h3").forEach((element, index) => {
      const entry = headings[index];
      if (entry) element.id = entry.id;
    });

    if (!scrollToHeading(root, id, "smooth")) return false;
    window.history.pushState(null, "", `#${id}`);
    return true;
  }

  return (
    <main className="submission-layout" aria-label="Candidate submission">
      <aside className="submission-toc panel" aria-label="Table of contents">
        <p className="submission-toc-title">On this page</p>
        <nav>
          <a className="submission-toc-top" href="#submission">
            Submission
          </a>
          {headings.map((heading) => (
            <a
              className={`submission-toc-link level-${heading.level}`}
              href={`#${heading.id}`}
              key={heading.id}
              onClick={(event) => {
                if (navigateToHeading(heading.id)) event.preventDefault();
              }}
            >
              {heading.title}
            </a>
          ))}
        </nav>
      </aside>
      <section className="panel submission-panel">
        <section
          id="submission"
          className="submission-markdown markdown-content"
          aria-label="Submission template"
          ref={markdownRef}
        >
          <Suspense fallback={<p>Loading submission template - one moment</p>}>
            <MarkdownRenderer>{markdown}</MarkdownRenderer>
          </Suspense>
        </section>
      </section>
    </main>
  );
}

function decodeHash(hash: string) {
  try {
    return decodeURIComponent(hash.replace(/^#/, ""));
  } catch {
    return hash.replace(/^#/, "");
  }
}

function scrollToHeading(root: HTMLElement, id: string, behavior: ScrollBehavior) {
  const target = Array.from(root.querySelectorAll<HTMLElement>("h2, h3")).find(
    (element) => element.id === id,
  );
  if (!target) return false;

  const rootTop = root.getBoundingClientRect().top;
  const targetTop = target.getBoundingClientRect().top;
  root.scrollTo({
    top: root.scrollTop + targetTop - rootTop - 12,
    behavior,
  });
  return true;
}
