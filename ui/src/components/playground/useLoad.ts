import { type DependencyList, useCallback, useEffect, useState } from "react";

export interface Loaded<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Runs `load` when `deps` change (or on `reload`), keeping the last data while reloading. */
export function useLoad<T>(load: () => Promise<T>, deps: DependencyList): Loaded<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [generation, setGeneration] = useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `load` is keyed by the caller's deps.
  useEffect(() => {
    let current = true;
    setLoading(true);
    load().then(
      (value) => {
        if (!current) return;
        setData(value);
        setError(null);
        setLoading(false);
      },
      (reason: unknown) => {
        if (!current) return;
        setError(reason instanceof Error ? reason.message : "Could not load.");
        setLoading(false);
      },
    );
    return () => {
      current = false;
    };
  }, [...deps, generation]);

  const reload = useCallback(() => setGeneration((value) => value + 1), []);
  return { data, error, loading, reload };
}
