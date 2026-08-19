import { useEffect, useState } from "react";

export const POLL_INTERVAL_MS = 3000;

export type LiveMode = "idle" | "sse" | "poll";

export function useFlowsLive(onChange: () => void, enabled: boolean): LiveMode {
  const [mode, setMode] = useState<LiveMode>("idle");

  useEffect(() => {
    if (!enabled) {
      setMode("idle");
      return;
    }
    let es: EventSource | null = null;
    let poll: number | undefined;
    let opened = false;

    const refresh = () => {
      onChange();
    };

    const startPoll = () => {
      if (poll !== undefined) {
        return;
      }
      setMode("poll");
      poll = window.setInterval(refresh, POLL_INTERVAL_MS);
    };

    // Exclusive fallback: close EventSource so the browser cannot keep
    // reconnecting while poll is the live path.
    const fallbackToPoll = () => {
      if (es !== null) {
        es.close();
        es = null;
      }
      startPoll();
    };

    try {
      es = new EventSource("/v1/events/stream");
      es.addEventListener("flow.inserted", refresh);
      es.addEventListener("flow.paused", refresh);
      es.addEventListener("store.wiped", refresh);
      es.onopen = () => {
        // close() can still deliver a queued open after fallbackToPoll.
        if (poll !== undefined || es === null) {
          return;
        }
        opened = true;
        setMode("sse");
      };
      es.onerror = () => {
        fallbackToPoll();
      };
    } catch {
      startPoll();
    }

    const watchdog = window.setTimeout(() => {
      if (!opened) {
        fallbackToPoll();
      }
    }, POLL_INTERVAL_MS);

    return () => {
      window.clearTimeout(watchdog);
      if (poll !== undefined) {
        window.clearInterval(poll);
      }
      if (es) {
        es.close();
      }
    };
  }, [enabled, onChange]);

  return mode;
}
