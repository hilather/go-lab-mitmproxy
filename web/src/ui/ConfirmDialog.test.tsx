import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { useConfirm } from "./ConfirmDialog";

function Harness({ onResult }: { onResult: (ok: boolean, extra: string) => void }) {
  const [renderDialog, confirm] = useConfirm();
  const [value, setValue] = useState("");
  const valueRef = useRef("");
  valueRef.current = value;
  return (
    <div>
      <button
        type="button"
        onClick={async () => {
          const ok = await confirm({ title: "Clear every captured flow?", body: "Deletes every flow.", confirmLabel: "Clear flows", danger: true });
          onResult(ok, valueRef.current);
        }}
      >
        Open
      </button>
      {renderDialog(
        <label>
          Generation
          <input value={value} onChange={(e) => setValue(e.target.value)} />
        </label>,
      )}
    </div>
  );
}

function ChainHarness({ onResult }: { onResult: (a: boolean, b: boolean) => void }) {
  const [renderDialog, confirm] = useConfirm();
  return (
    <div>
      <button
        type="button"
        onClick={async () => {
          const a = await confirm({ title: "Turn the UI off?", body: "First.", confirmLabel: "Continue" });
          if (!a) return onResult(false, false);
          const b = await confirm({ title: "Evict flows?", body: "Second.", confirmLabel: "Apply and evict", danger: true });
          onResult(a, b);
        }}
      >
        Apply
      </button>
      {renderDialog()}
    </div>
  );
}

describe("useConfirm", () => {
  it("cancel resolves false, with initial focus on Cancel and focus returned to the opener", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<Harness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Clear every captured flow?" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(dialog).toHaveAccessibleDescription("Deletes every flow.");
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(screen.getByRole("button", { name: "Clear flows" })).toHaveClass("btn-danger-fill");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onResult).toHaveBeenCalledWith(false, "");
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Open" })).toHaveFocus();
  });

  it("a second confirm in a row starts with focus on Cancel, never on the dangerous button", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<ChainHarness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Apply" }));
    await screen.findByRole("alertdialog", { name: "Turn the UI off?" });
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByRole("alertdialog", { name: "Evict flows?" });
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(screen.getByRole("button", { name: "Apply and evict" })).not.toHaveFocus();
    await user.keyboard("{Enter}");
    expect(onResult).toHaveBeenCalledWith(true, false);
  });

  it("Escape resolves false", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<Harness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    await screen.findByRole("alertdialog");
    await user.keyboard("{Escape}");
    expect(onResult).toHaveBeenCalledWith(false, "");
  });

  it("confirm resolves true and live extra content is read after await", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    render(<Harness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    await user.type(await screen.findByLabelText("Generation"), "7");
    await user.click(screen.getByRole("button", { name: "Clear flows" }));
    expect(onResult).toHaveBeenCalledWith(true, "7");
  });

  it("renders into a body-level host and resolves false on unmount", async () => {
    const user = userEvent.setup();
    const onResult = vi.fn();
    const view = render(<Harness onResult={onResult} />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog.closest(".modal-host")?.parentElement).toBe(document.body);
    expect(view.container.closest("[inert]") ?? view.container.parentElement?.hasAttribute("inert")).toBeTruthy();
    await act(async () => view.unmount());
    expect(onResult).toHaveBeenCalledWith(false, "");
  });
});
