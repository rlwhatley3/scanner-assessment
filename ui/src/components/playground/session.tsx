import { createContext, type ReactNode, useContext, useState } from "react";
import type { ScanSession } from "./api.ts";

interface ActiveSession {
  /** The scan session new scans go into. One at a time; not kept across reloads. */
  session: ScanSession | null;
  setSession: (session: ScanSession | null) => void;
}

const ActiveSessionContext = createContext<ActiveSession | null>(null);

export function ActiveSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<ScanSession | null>(null);
  return (
    <ActiveSessionContext.Provider value={{ session, setSession }}>
      {children}
    </ActiveSessionContext.Provider>
  );
}

export function useActiveSession(): ActiveSession {
  const value = useContext(ActiveSessionContext);
  if (!value) throw new Error("useActiveSession must be used inside ActiveSessionProvider.");
  return value;
}
