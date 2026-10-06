import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

export type ConfirmOptions = {
  title: string;
  body?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  danger?: boolean;
};

type Pending = ConfirmOptions & { resolve: (ok: boolean) => void; opener: Element | null; seq: number };

export const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function nativelyDisabled(opener: HTMLElement): boolean {
  return (
    (opener instanceof HTMLButtonElement ||
      opener instanceof HTMLInputElement ||
      opener instanceof HTMLSelectElement ||
      opener instanceof HTMLTextAreaElement) &&
    opener.disabled
  );
}

/**
 * focusTarget picks where a closing surface should move focus.
 * A usable opener is a connected HTMLElement other than body/documentElement
 * that is not natively disabled and not aria-disabled. Otherwise #app-main, or null.
 * Tabindex is not touched here.
 */
export function focusTarget(opener: Element | null): HTMLElement | null {
  if (
    opener instanceof HTMLElement &&
    opener.isConnected &&
    opener !== document.body &&
    opener !== document.documentElement &&
    !nativelyDisabled(opener) &&
    opener.getAttribute("aria-disabled") !== "true"
  ) {
    return opener;
  }
  const main = document.getElementById("app-main");
  return main instanceof HTMLElement ? main : null;
}

/**
 * useInertBackground marks every body child except the dialog host inert while
 * a modal surface is open, and restores the previous values on close. Focus
 * returns to the opener, or a getter read at cleanup, only after inert is removed
 * (an inert element cannot take focus).
 */
export function useInertBackground(
  open: boolean,
  host: HTMLElement | null,
  opener: Element | null | (() => Element | null) = null,
) {
  useEffect(() => {
    if (!open || host === null) return;
    const touched: { el: Element; had: boolean }[] = [];
    for (const el of Array.from(document.body.children)) {
      if (el === host || el.contains(host) || el.tagName === "SCRIPT") continue;
      touched.push({ el, had: el.hasAttribute("inert") });
      el.setAttribute("inert", "");
    }
    return () => {
      for (const { el, had } of touched) if (!had) el.removeAttribute("inert");
      const o = typeof opener === "function" ? opener() : opener;
      const t = focusTarget(o);
      // Main content container (plain div, not a landmark); make it programmatically focusable once.
      if (t !== null && t.id === "app-main" && !t.hasAttribute("tabindex")) t.tabIndex = -1;
      t?.focus();
    };
    // opener (or its getter) is read only at cleanup; it is not a dependency because re-running the effect would drop and re-apply inert mid-session (the plan-review getter is a new function every render).
  }, [open, host]);
}

/** trapTab keeps Tab/Shift+Tab focus inside the dialog element. */
export function trapTab(event: React.KeyboardEvent<HTMLElement>, root: HTMLElement | null) {
  if (event.key !== "Tab" || root === null) return;
  const items = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE));
  if (items.length === 0) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (first === undefined || last === undefined) return;
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

/** usePortalHost creates a body-level host element for modal surfaces. */
export function usePortalHost(open: boolean): HTMLElement | null {
  const [host, setHost] = useState<HTMLElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const el = document.createElement("div");
    el.className = "modal-host";
    document.body.appendChild(el);
    setHost(el);
    return () => {
      el.remove();
      setHost(null);
    };
  }, [open]);
  return host;
}

/**
 * useConfirm replaces window.confirm with an in-page alert dialog.
 * Returns [renderDialog, confirm]: render `renderDialog(extra)` in the page
 * (extra is live content such as an optional input), and `await confirm(opts)`.
 * Cancel, Escape and unmount resolve false.
 */
export function useConfirm(): [(extra?: ReactNode) => ReactNode, (opts: ConfirmOptions) => Promise<boolean>] {
  const [pending, setPending] = useState<Pending | null>(null);
  const pendingRef = useRef<Pending | null>(null);
  const seqRef = useRef(0);
  pendingRef.current = pending;

  useEffect(
    () => () => {
      pendingRef.current?.resolve(false);
    },
    [],
  );

  const confirm = useCallback((opts: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      const opener = pendingRef.current?.opener ?? document.activeElement;
      pendingRef.current?.resolve(false);
      seqRef.current++;
      setPending({ ...opts, resolve, opener, seq: seqRef.current });
    });
  }, []);

  const close = useCallback((ok: boolean) => {
    const current = pendingRef.current;
    if (current === null) return;
    pendingRef.current = null;
    setPending(null);
    current.resolve(ok);
    // Focus returns to the opener in useInertBackground's cleanup, after inert is removed.
  }, []);

  const render = (extra?: ReactNode) =>
    pending === null ? null : <ConfirmSurface key={pending.seq} pending={pending} extra={extra} onClose={close} />;
  return [render, confirm];
}

function ConfirmSurface({
  pending,
  extra,
  onClose,
}: {
  pending: Pending;
  extra?: ReactNode;
  onClose: (ok: boolean) => void;
}) {
  const host = usePortalHost(true);
  useInertBackground(true, host, pending.opener);
  const ref = useRef<HTMLDivElement | null>(null);
  const cancelRef = useRef<HTMLButtonElement | null>(null);
  const titleId = useId();
  const bodyId = useId();
  useEffect(() => {
    if (host !== null) cancelRef.current?.focus();
  }, [host]);
  if (host === null) return null;
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) { e.preventDefault(); onClose(false); } }}>
      <div
        ref={ref}
        className={`modal card${pending.danger ? " modal-danger" : ""}`}
        role="alertdialog"
        tabIndex={-1}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={pending.body ? bodyId : undefined}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            e.stopPropagation();
            onClose(false);
          } else trapTab(e, ref.current);
        }}
      >
        <h2 id={titleId} className="modal-title">
          {pending.title}
        </h2>
        {pending.body ? (
          <div id={bodyId} className="modal-body">
            {pending.body}
          </div>
        ) : null}
        {extra ? <div className="modal-extra">{extra}</div> : null}
        <div className="modal-actions">
          <button type="button" ref={cancelRef} onClick={() => onClose(false)}>
            {pending.cancelLabel ?? "Cancel"}
          </button>
          <button
            type="button"
            className={pending.danger ? "btn-danger-fill" : "primary"}
            onClick={() => onClose(true)}
          >
            {pending.confirmLabel}
          </button>
        </div>
      </div>
    </div>,
    host,
  );
}
