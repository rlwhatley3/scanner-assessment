import { useEffect, useState } from "react";
import { checkHealth } from "./api.ts";

export type ApiHealth = "checking" | "online" | "offline";

const POLL_MS = 10_000;

/** Polls `/api/health` so the playground can show whether the API is reachable. */
export function useApiHealth(): ApiHealth {
  const [health, setHealth] = useState<ApiHealth>("checking");

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        setHealth((await checkHealth(controller.signal)) ? "online" : "offline");
      } catch {
        return; // Aborted on unmount.
      }
      timer = setTimeout(poll, POLL_MS);
    }

    poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, []);

  return health;
}
