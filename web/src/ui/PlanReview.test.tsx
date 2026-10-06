import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import type { ConfigurationPlan, ReviewedChange } from "../api/configuration";
import { PlanReview, usePlanReview } from "./PlanReview";

const change: ReviewedChange = {
  expectedRevision: "sha256:1111111111111111111111",
  idempotencyKey: "key-1",
  reason: "lab",
  force: false,
  operations: [{ op: "replace", path: "spec.protocols.http2.enabled", value: true }],
};
const plan: ConfigurationPlan = {
  previousRevision: "sha256:1111111111111111111111",
  candidateRevision: "sha256:2222222222222222222222",
  drifted: true,
  diff: [{ path: "spec.protocols.http2.enabled", op: "replace", before: false, after: true }],
  warnings: [{ code: "live_next_connection", message: "Applies to new connections." }],
} as ConfigurationPlan;

describe("PlanReview", () => {
  it("renders revisions, kv, diff, warnings and always-rendered raw JSON", () => {
    render(<PlanReview change={change} plan={plan} onApply={vi.fn()} onDiscard={vi.fn()} applyDisabled={false} discardDisabled={false} />);
    expect(screen.getByTitle(plan.candidateRevision)).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Planned diff" })).toHaveTextContent("spec.protocols.http2.enabled");
    expect(screen.getAllByText(/live_next_connection/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Applies to new connections/, { selector: ":not(pre)" })).toBeInTheDocument();
    expect(screen.getByText("Raw request and plan JSON").closest("details")?.textContent).toContain('"idempotencyKey": "key-1"');
  });

  it("honours caller-owned disabling for Apply and Discard", () => {
    render(<PlanReview change={change} plan={plan} onApply={vi.fn()} onDiscard={vi.fn()} applyDisabled discardDisabled />);
    expect(screen.getByRole("button", { name: "Apply reviewed changes" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard plan" })).toBeDisabled();
  });
});

function DrawerHarness({ onResult }: { onResult: (ok: boolean) => void }) {
  const [drawer, review] = usePlanReview();
  return (
    <>
      <button type="button" onClick={async () => onResult(await review(change, plan))}>
        Review
      </button>
      {drawer}
    </>
  );
}

describe("usePlanReview drawer", () => {
  it("settles once even on a double click of Apply", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<DrawerHarness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Review" }));
    const apply = await screen.findByRole("button", { name: "Apply reviewed changes" });
    expect(screen.getByRole("dialog", { name: "Review planned change" })).toBeInTheDocument();
    // Both clicks land before React re-renders (one act scope), so the second reaches the still-mounted
    // Apply and calls close() again with pendingRef already cleared. The guard must make that a no-op:
    // without it close() dereferences null and the click handler throws.
    const errors: unknown[] = [];
    const onError = (event: ErrorEvent) => {
      errors.push(event.error);
      event.preventDefault();
    };
    window.addEventListener("error", onError);
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      act(() => {
        fireEvent.click(apply);
        expect(apply.isConnected).toBe(true);
        fireEvent.click(apply);
      });
      await act(async () => {});
      expect(errors).toEqual([]);
      expect(consoleError).not.toHaveBeenCalled();
    } finally {
      window.removeEventListener("error", onError);
      consoleError.mockRestore();
    }
    expect(onResult).toHaveBeenCalledTimes(1);
    expect(onResult).toHaveBeenCalledWith(true);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Escape and Discard resolve false", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<DrawerHarness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Review" }));
    await screen.findByRole("dialog");
    await user.keyboard("{Escape}");
    expect(onResult).toHaveBeenLastCalledWith(false);
    await user.click(screen.getByRole("button", { name: "Review" }));
    await user.click(await screen.findByRole("button", { name: "Discard plan" }));
    expect(onResult).toHaveBeenLastCalledWith(false);
    expect(onResult).toHaveBeenCalledTimes(2);
  });

  it("backdrop mousedown is default-prevented and cancels", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<DrawerHarness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Review" }));
    const dialog = await screen.findByRole("dialog", { name: "Review planned change" });
    const backdrop = dialog.parentElement;
    if (!(backdrop instanceof HTMLElement)) throw new Error("backdrop missing");
    expect(backdrop).toHaveClass("drawer-backdrop");
    // jsdom has no mousedown focus move, so this only checks preventDefault and that the surface closes.
    expect(fireEvent.mouseDown(backdrop)).toBe(false);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

type FocusMode = "escape" | "discard" | "apply" | "ordering" | "enabled" | "capture";

function FocusHarness({ mode }: { mode: FocusMode }) {
  const [drawer, review] = usePlanReview();
  const [disabled, setDisabled] = useState(false);
  const emulateFixup = mode === "escape" || mode === "discard" || mode === "apply";
  return (
    <>
      <div id="app-main" />
      <button
        type="button"
        disabled={disabled}
        onClick={async (e) => {
          const opener = e.currentTarget;
          if (mode === "ordering") {
            setDisabled(true);
            await review(change, plan, opener);
            return;
          }
          if (emulateFixup) {
            setDisabled(true);
            (document.activeElement as HTMLElement).blur();
          }
          if (mode === "capture") {
            await review(change, plan);
          } else {
            await review(change, plan, opener);
          }
        }}
      >
        Open review
      </button>
      {drawer}
    </>
  );
}

async function openReview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: "Open review" }));
  await screen.findByRole("dialog", { name: "Review planned change" });
}

describe("usePlanReview focus restore", () => {
  it("Escape returns focus to #app-main when the opener was disabled and blurred", async () => {
    const user = userEvent.setup();
    render(<FocusHarness mode="escape" />);
    await openReview(user);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.getElementById("app-main")).toHaveFocus();
  });

  it("Discard returns focus to #app-main when the opener was disabled and blurred", async () => {
    const user = userEvent.setup();
    render(<FocusHarness mode="discard" />);
    await openReview(user);
    await user.click(screen.getByRole("button", { name: "Discard plan" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.getElementById("app-main")).toHaveFocus();
  });

  it("Apply returns focus to #app-main when the opener was disabled and blurred", async () => {
    const user = userEvent.setup();
    render(<FocusHarness mode="apply" />);
    await openReview(user);
    await user.click(screen.getByRole("button", { name: "Apply reviewed changes" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.getElementById("app-main")).toHaveFocus();
  });

  it("decides the restore target at close, before a later re-enable", async () => {
    const user = userEvent.setup();
    render(<FocusHarness mode="ordering" />);
    await openReview(user);
    const opener = screen.getByRole("button", { name: "Open review" });
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        (opener as HTMLButtonElement).disabled = false;
      }
    };
    document.addEventListener("keydown", onKeyDown);
    try {
      await user.keyboard("{Escape}");
    } finally {
      document.removeEventListener("keydown", onKeyDown);
    }
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.getElementById("app-main")).toHaveFocus();
  });

  it("returns focus to an opener that is still enabled at close", async () => {
    const user = userEvent.setup();
    render(<FocusHarness mode="enabled" />);
    await openReview(user);
    await user.keyboard("{Escape}");
    expect(screen.getByRole("button", { name: "Open review" })).toHaveFocus();
  });

  it("review(change, plan) with no third arg still captures document.activeElement", async () => {
    const user = userEvent.setup();
    render(<FocusHarness mode="capture" />);
    await openReview(user);
    await user.keyboard("{Escape}");
    expect(screen.getByRole("button", { name: "Open review" })).toHaveFocus();
  });
});
