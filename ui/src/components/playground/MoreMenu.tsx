import { type ReactNode, useEffect, useRef } from "react";

export interface MoreMenuItem {
  label: string;
  onSelect: () => void;
  disabled?: boolean;
  title?: string;
}

/** A "More" button that opens a short list of less common actions. */
export default function MoreMenu({ label, items }: { label: ReactNode; items: MoreMenuItem[] }) {
  const ref = useRef<HTMLDetailsElement>(null);

  // Close on a click outside or Escape, like a native menu.
  useEffect(() => {
    function close(event: Event) {
      const menu = ref.current;
      if (!menu?.open) return;
      const outside =
        event instanceof KeyboardEvent
          ? event.key === "Escape"
          : !menu.contains(event.target as Node);
      if (outside) menu.open = false;
    }
    document.addEventListener("click", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("keydown", close);
    };
  }, []);

  return (
    <details className="more-menu" ref={ref}>
      <summary className="button">{label}</summary>
      <ul>
        {items.map((item) => (
          <li key={item.label}>
            <button
              type="button"
              className="more-menu-item"
              disabled={item.disabled}
              title={item.title}
              onClick={() => {
                if (ref.current) ref.current.open = false;
                item.onSelect();
              }}
            >
              {item.label}
            </button>
          </li>
        ))}
      </ul>
    </details>
  );
}
