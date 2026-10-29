import { createContext, type ReactNode, useContext, useState } from "react";
import type { ScanSession } from "./api.ts";

interface ActiveSession {
  /** The scan session new scans go into. One at a time; not kept across reloads. */
  session: ScanSession | null;
  setSession: (session: ScanSession | null) => void;
  /** The rule set version the next scan starts a session with, while no session is open. Null
   * picks the first rule set's newest version. */
  versionChoice: number | null;
  setVersionChoice: (versionId: number | null) => void;
}

const ActiveSessionContext = createContext<ActiveSession | null>(null);

export function ActiveSessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<ScanSession | null>(null);
  const [versionChoice, setVersionChoice] = useState<number | null>(null);
  return (
    <ActiveSessionContext.Provider value={{ session, setSession, versionChoice, setVersionChoice }}>
      {children}
    </ActiveSessionContext.Provider>
  );
}

export function useActiveSession(): ActiveSession {
  const value = useContext(ActiveSessionContext);
  if (!value) throw new Error("useActiveSession must be used inside ActiveSessionProvider.");
  return value;
}
