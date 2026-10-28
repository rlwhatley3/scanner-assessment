import type { SyntheticEvent } from "react";
import "./style.css";

function hideSwaggerBranding(event: SyntheticEvent<HTMLIFrameElement>) {
  const document = event.currentTarget.contentDocument;
  if (!document) return;

  const rootStyles = getComputedStyle(window.document.documentElement);
  for (let index = 0; index < rootStyles.length; index += 1) {
    const property = rootStyles.item(index);
    if (property.startsWith("--")) {
      document.documentElement.style.setProperty(property, rootStyles.getPropertyValue(property));
    }
  }

  const style = document.createElement("style");
  style.textContent = `
    html, body { color-scheme: light !important; background: var(--page) !important; }
    .topbar { display: none !important; }
    .swagger-ui { color: var(--ink); background: transparent; font-family: inherit; }
    .swagger-ui .info { margin-top: 1.75rem; }
  `;
  document.head.append(style);
}

export default function ApiDocsView() {
  const swaggerUrl = new URL(
    "swagger-ui/",
    new URL(import.meta.env.BASE_URL, window.location.origin),
  ).toString();

  return (
    <main className="docs-panel">
      <iframe
        title="Secrets Scanner API documentation"
        src={swaggerUrl}
        className="docs-frame"
        onLoad={hideSwaggerBranding}
      />
    </main>
  );
}
