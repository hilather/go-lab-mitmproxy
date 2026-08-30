import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { APIError, getState } from "./client";
import type { StateView } from "./types";

export type LiveSpecValue = {
  state: StateView | null;
  refresh: () => Promise<void>;
  error: string;
};

const defaultLiveSpec: LiveSpecValue = {
  state: null,
  refresh: async () => {},
  error: "",
};

const LiveSpecContext = createContext<LiveSpecValue>(defaultLiveSpec);

export function useLiveSpec(): LiveSpecValue {
  return useContext(LiveSpecContext);
}

export function interceptChipLabel(state: StateView | null): string {
  if (state === null) {
    return "intercept ports unknown";
  }
  const tls = state.canonical?.spec?.tls;
  if (tls == null) {
    return "intercept ports unknown";
  }
  if (!tls.intercept) {
    return "intercept off";
  }
  const ports = Array.isArray(tls.ports) ? tls.ports : [];
  if (ports.length === 0) {
    return "intercept ports unknown";
  }
  return `:${ports.join(",")} intercept`;
}

export function LiveSpecProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<StateView | null>(null);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const next = await getState();
      setState(next);
      setError("");
    } catch (err) {
      setError(err instanceof APIError ? err.message : "Could not load state.");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return <LiveSpecContext.Provider value={{ state, refresh, error }}>{children}</LiveSpecContext.Provider>;
}

export function InterceptChip() {
  const { state } = useLiveSpec();
  return <span className="chip">{interceptChipLabel(state)}</span>;
}
