import { lazy, StrictMode, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import ApiDocsView from "./components/docs/ApiDocsView";
import McpDocsView from "./components/docs/McpDocsView";
import InstructionsView from "./components/instructions/InstructionsView";
import ApplicationNavigation from "./components/layout/ApplicationNavigation";
import PlaygroundView from "./components/playground/PlaygroundView";
import SubmissionView from "./components/submission/SubmissionView";
import "streamdown/styles.css";
import "./style.css";

const appBasePath = import.meta.env.BASE_URL.replace(/\/$/, "") || "/";
const WhiteboardView = lazy(() =>
  import("./components/whiteboard/Whiteboard").then(({ Whiteboard }) => ({
    default: Whiteboard,
  })),
);

function App() {
  return (
    <BrowserRouter basename={appBasePath}>
      <ApplicationNavigation />
      <Routes>
        <Route path="/" element={<Navigate to="/instructions" replace />} />
        <Route path="/instructions" element={<InstructionsView />} />
        <Route path="/playground/*" element={<PlaygroundView />} />
        <Route path="/submission" element={<SubmissionView />} />
        <Route
          path="/whiteboard"
          element={
            <Suspense
              fallback={<div className="whiteboard-loading">Loading whiteboard - one moment</div>}
            >
              <WhiteboardView />
            </Suspense>
          }
        />
        <Route path="/api-docs" element={<ApiDocsView />} />
        <Route path="/mcp-docs" element={<McpDocsView />} />
        <Route path="*" element={<Navigate to="/instructions" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Could not find the app root element.");
}

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
