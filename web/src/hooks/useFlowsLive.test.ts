import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { POLL_INTERVAL_MS, useFlowsLive } from "./useFlowsLive";

class FakeEventSource {
  static fail = false;
  static instances: FakeEventSource[] = [];
  onopen: ((ev: Event) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  closed = false;
  readonly listeners = new Map<string, Set<(ev: MessageEvent<string>) => void>>();

  constructor(public readonly url: string) {
    FakeEventSource.instances.push(this);
    if (FakeEventSource.fail) {
      throw new Error("EventSource unavailable");
    }
  }

  addEventListener(type: string, fn: (ev: MessageEvent<string>) => void): void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(fn);
    this.listeners.set(type, set);
  }

  removeEventListener(): void {}

  close(): void {
    this.closed = true;
  }
}

describe("useFlowsLive", () => {
  afterEach(() => {
    FakeEventSource.fail = false;
    FakeEventSource.instances = [];
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("uses EventSource when it opens", () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    const onChange = vi.fn();
    const { result } = renderHook(() => useFlowsLive(onChange, true));
    act(() => {
      FakeEventSource.instances[0]?.onopen?.(new Event("open"));
    });
    expect(result.current).toBe("sse");
    expect(FakeEventSource.instances[0]?.url).toBe("/v1/events/stream");
    expect(FakeEventSource.instances[0]?.closed).toBe(false);
    expect(FakeEventSource.instances[0]?.listeners.has("flow.inserted")).toBe(true);
  });

  it("polls every 3s when EventSource cannot be constructed", () => {
    FakeEventSource.fail = true;
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.useFakeTimers();
    const onChange = vi.fn();
    const { result } = renderHook(() => useFlowsLive(onChange, true));
    expect(result.current).toBe("poll");
    expect(onChange).not.toHaveBeenCalled();
    act(() => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    expect(onChange).toHaveBeenCalledTimes(1);
    act(() => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    expect(onChange).toHaveBeenCalledTimes(2);
  });

  it("closes EventSource on error and switches exclusively to poll", () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.useFakeTimers();
    const onChange = vi.fn();
    const { result } = renderHook(() => useFlowsLive(onChange, true));
    const inst = FakeEventSource.instances[0];
    if (!inst) {
      throw new Error("expected EventSource");
    }
    act(() => {
      inst.onopen?.(new Event("open"));
    });
    expect(result.current).toBe("sse");
    act(() => {
      inst.onerror?.(new Event("error"));
    });
    expect(inst.closed).toBe(true);
    expect(result.current).toBe("poll");
    act(() => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it("watchdog closes a never-opened EventSource and starts poll", () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.useFakeTimers();
    const onChange = vi.fn();
    const { result } = renderHook(() => useFlowsLive(onChange, true));
    const inst = FakeEventSource.instances[0];
    if (!inst) {
      throw new Error("expected EventSource");
    }
    expect(result.current).toBe("idle");
    act(() => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    expect(inst.closed).toBe(true);
    expect(result.current).toBe("poll");
    act(() => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it("ignores onopen after the watchdog has fallen back to poll", () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.useFakeTimers();
    const onChange = vi.fn();
    const { result } = renderHook(() => useFlowsLive(onChange, true));
    const inst = FakeEventSource.instances[0];
    if (!inst) {
      throw new Error("expected EventSource");
    }
    act(() => {
      vi.advanceTimersByTime(POLL_INTERVAL_MS);
    });
    expect(result.current).toBe("poll");
    act(() => {
      inst.onopen?.(new Event("open"));
    });
    expect(result.current).toBe("poll");
  });
});
