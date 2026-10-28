import { useCallback, useEffect, useRef, useState } from "react";
import { type Editor, FrameShapeUtil, type TLEditorSnapshot, Tldraw } from "tldraw";
import "tldraw/tldraw.css";
import savedWhiteboardTemplate from "../../whiteboard-template.tldraw.json";
import "./style.css";

type SaveState = "loading" | "saved" | "unsaved" | "saving" | "error";

const DEFAULT_BOARD = "whiteboard";

const DEFAULT_SNAPSHOT = savedWhiteboardTemplate as unknown as TLEditorSnapshot;

const SHAPE_UTILS = [FrameShapeUtil.configure({ showColors: true })];

function whiteboardApiUrl(path: string): string {
  const baseUrl = new URL(import.meta.env.BASE_URL, window.location.origin);
  return new URL(path.replace(/^\/+/, ""), baseUrl).toString();
}

function createDefaultSnapshot(): TLEditorSnapshot {
  return {
    ...DEFAULT_SNAPSHOT,
    session: {
      ...DEFAULT_SNAPSHOT.session,
      pageStates: (DEFAULT_SNAPSHOT.session.pageStates ?? []).map((pageState) => ({
        ...pageState,
        selectedShapeIds: [],
      })),
    },
  };
}

async function loadBoard(): Promise<TLEditorSnapshot | null> {
  const response = await fetch(whiteboardApiUrl(`/api/whiteboards/${DEFAULT_BOARD}`));
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Could not load the shared whiteboard (HTTP ${response.status}).`);
  }
  return (await response.json()) as TLEditorSnapshot;
}

async function putBoard(snapshot: TLEditorSnapshot): Promise<void> {
  const response = await fetch(
    whiteboardApiUrl(`/api/whiteboards/${encodeURIComponent(DEFAULT_BOARD)}`),
    {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(snapshot),
    },
  );
  if (!response.ok) {
    const detail = (await response.text()).trim();
    throw new Error(
      `Could not save "${DEFAULT_BOARD}" (HTTP ${response.status})${detail ? `: ${detail}` : "."}`,
    );
  }
}

export function Whiteboard() {
  const [snapshot, setSnapshot] = useState<TLEditorSnapshot | null>(null);
  const [boardReady, setBoardReady] = useState(false);
  const [isNewBoard, setIsNewBoard] = useState(false);
  const [saveState, setSaveState] = useState<SaveState>("loading");
  const [error, setError] = useState("");
  const editorRef = useRef<Editor | null>(null);
  const saveTimer = useRef<number | null>(null);
  const saveQueue = useRef<Promise<void>>(Promise.resolve());

  useEffect(() => {
    const watermarkStyles = document.createElement("style");
    watermarkStyles.textContent = ".tl-watermark_SEE-LICENSE { display: none !important; }";
    document.head.append(watermarkStyles);
    return () => watermarkStyles.remove();
  }, []);

  const enqueueSave = useCallback((nextSnapshot: TLEditorSnapshot) => {
    const queuedSave = saveQueue.current.catch(() => undefined).then(() => putBoard(nextSnapshot));
    saveQueue.current = queuedSave;
    return queuedSave;
  }, []);

  const persistSnapshot = useCallback(
    async (nextSnapshot: TLEditorSnapshot) => {
      setSaveState("saving");
      try {
        await enqueueSave(nextSnapshot);
        setSaveState("saved");
        setError("");
      } catch {
        setSaveState("error");
        setError("Save failed. Your drawing is still in this browser; try saving again.");
      }
    },
    [enqueueSave],
  );

  const scheduleSave = useCallback(
    (editor: Editor) => {
      setSaveState("unsaved");
      if (saveTimer.current !== null) window.clearTimeout(saveTimer.current);
      saveTimer.current = window.setTimeout(() => {
        saveTimer.current = null;
        void persistSnapshot(editor.getSnapshot());
      }, 700);
    },
    [persistSnapshot],
  );

  useEffect(() => {
    let cancelled = false;
    async function initialize() {
      try {
        const savedSnapshot = await loadBoard();
        if (cancelled) return;
        if (savedSnapshot) {
          setSnapshot(savedSnapshot);
          setIsNewBoard(false);
          setSaveState("saved");
        } else {
          setSnapshot(createDefaultSnapshot());
          setIsNewBoard(true);
          setSaveState("unsaved");
        }
        setBoardReady(true);
      } catch (cause) {
        if (cancelled) return;
        setError(cause instanceof Error ? cause.message : "Could not open the shared whiteboard.");
        setSaveState("error");
      }
    }

    void initialize();
    return () => {
      cancelled = true;
      if (saveTimer.current !== null) window.clearTimeout(saveTimer.current);
    };
  }, []);

  const handleMount = useCallback(
    (editor: Editor) => {
      editorRef.current = editor;
      const stopListening = editor.store.listen(() => scheduleSave(editor), {
        scope: "document",
        source: "user",
      });
      editor.updateInstanceState({ isGridMode: true });
      editor.user.updateUserPreferences({
        isDynamicSizeMode: true,
        isPasteAtCursorMode: true,
        isSnapMode: true,
      });
      // Only the first page is "Whiteboard"; later pages, like the flow board, keep their names.
      const [firstPage] = editor.getPages();
      if (firstPage && firstPage.name !== "Whiteboard") {
        editor.renamePage(firstPage, "Whiteboard");
      }

      if (isNewBoard) {
        void persistSnapshot(editor.getSnapshot());
      }
      return () => {
        stopListening();
        if (saveTimer.current !== null) window.clearTimeout(saveTimer.current);
        void enqueueSave(editor.getSnapshot()).catch(() => undefined);
        editorRef.current = null;
      };
    },
    [enqueueSave, isNewBoard, persistSnapshot, scheduleSave],
  );

  function resetBoard() {
    const editor = editorRef.current;
    if (!editor) return;
    if (
      !window.confirm(
        "Reset the shared whiteboard? This replaces the saved drawing with its starting layout and cannot be undone.",
      )
    ) {
      return;
    }

    const defaultSnapshot = createDefaultSnapshot();
    editor.loadSnapshot(defaultSnapshot);
    void persistSnapshot(editor.getSnapshot());
  }

  return (
    <main className="whiteboard-page">
      <div className="visually-hidden" aria-live="polite" role="status">
        {error || (saveState === "saving" ? "Saving whiteboard" : "")}
      </div>
      <button
        type="button"
        className="whiteboard-reset-button"
        onClick={resetBoard}
        disabled={!boardReady}
      >
        Reset whiteboard
      </button>
      <section className="whiteboard-canvas" aria-label="Tldraw whiteboard">
        {boardReady ? (
          <Tldraw
            colorScheme="light"
            licenseKey={import.meta.env.VITE_TLDRAW_LICENSE_KEY}
            snapshot={snapshot ?? undefined}
            shapeUtils={SHAPE_UTILS}
            onMount={handleMount}
          />
        ) : (
          <div className="whiteboard-loading">
            {error || "Preparing your saved whiteboard - one moment"}
          </div>
        )}
      </section>
    </main>
  );
}
