import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { ConfigurationPlan, ReviewedChange } from "../api/configuration";
import { focusTarget, trapTab, useInertBackground, usePortalHost } from "./ConfirmDialog";

/** shortRevision renders sha256:abcd…wxyz; the full value goes in a title. */
export function shortRevision(rev: string | undefined): string {
  if (!rev) return "—";
  const m = /^([a-z0-9]+:)?(.*)$/.exec(rev);
  const prefix = m?.[1] ?? "";
  const hex = m?.[2] ?? rev;
  return hex.length > 12 ? `${prefix}${hex.slice(0, 4)}…${hex.slice(-4)}` : rev;
}

export function RevisionChip({ rev, tone = "" }: { rev: string | undefined; tone?: string }) {
  return (
    <span className={`chip mono ${tone}`} title={rev}>
      {shortRevision(rev)}
    </span>
  );
}

function compact(value: unknown): string {
  if (value === undefined) return "—";
  return JSON.stringify(value);
}

/** DiffTable renders plan/audit diff rows: path, op, before (danger), after (ok). */
export function DiffTable({ diff, label = "Planned diff" }: { diff: ConfigurationPlan["diff"] | undefined; label?: string }) {
  const rows = diff ?? [];
  if (rows.length === 0) return <p className="note">No changes: the candidate matches the current runtime.</p>;
  return (
    <table className="data diff" aria-label={label}>
      <thead>
        <tr>
          <th>Path</th>
          <th>Op</th>
          <th>Before</th>
          <th>After</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={`${row.path}-${i}`}>
            <td>{row.path}</td>
            <td>{row.op}</td>
            <td className="before">{compact(row.before)}</td>
            <td className="after">{compact(row.after)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function PlanWarnings({ plan }: { plan: Pick<ConfigurationPlan, "warnings" | "drifted"> }) {
  return (
    <>
      {(plan.warnings ?? []).map((w, i) => (
        <p key={`${w.code}-${i}`} className={`note ${w.code === "store_evict" ? "note-danger" : "note-warn"}`}>
          <span className="mono">{w.code}</span>
          <span>{w.message}</span>
        </p>
      ))}
      {plan.drifted ? (
        <p className="note note-warn">
          <span className="mono">drifted</span>
          <span>Runtime differs from bootstrap. Reset would revert live changes.</span>
        </p>
      ) : null}
    </>
  );
}

/**
 * PlanReview shows a reviewed change and its plan before apply: revision
 * chips, request summary, diff table, warning/drift callouts and the raw
 * request + plan JSON (always rendered inside a closed <details>).
 */
export function PlanReview({
  change,
  plan,
  onApply,
  onDiscard,
  applyDisabled,
  discardDisabled,
  title = "Review planned changes",
  headingId,
}: {
  change: ReviewedChange;
  plan: ConfigurationPlan;
  onApply: () => void;
  onDiscard: () => void;
  applyDisabled: boolean;
  /** Discard is caller-owned too: Configuration passes `busy` (as today); the Status drawer passes false. */
  discardDisabled: boolean;
  title?: string;
  headingId?: string;
}) {
  return (
    <section className="card plan-review" aria-labelledby={headingId}>
      <div className="card-h">
        <h2 id={headingId}>{title}</h2>
        <span className="chip">{(plan.diff ?? []).length} changes</span>
      </div>
      <div className="card-b plan-review">
        <div className="rev-chips" aria-label="Revisions">
          <RevisionChip rev={plan.previousRevision} />
          <span aria-hidden="true">→</span>
          <span className="visually-hidden">to</span>
          <RevisionChip rev={plan.candidateRevision} tone="chip-accent" />
        </div>
        <dl className="kv">
          <div>
            <dt>Expected revision</dt>
            <dd title={change.expectedRevision}>{shortRevision(change.expectedRevision)}</dd>
          </div>
          <div>
            <dt>Idempotency key</dt>
            <dd>{change.idempotencyKey}</dd>
          </div>
          <div>
            <dt>Reason</dt>
            <dd>{change.reason || "—"}</dd>
          </div>
          <div>
            <dt>Force</dt>
            <dd className={change.force ? "danger-text" : undefined}>{String(change.force)}</dd>
          </div>
          <div>
            <dt>Operations</dt>
            <dd>{change.operations.map((o) => o.op).join(", ")}</dd>
          </div>
        </dl>
        <DiffTable diff={plan.diff} />
        <PlanWarnings plan={plan} />
        <details>
          <summary>Raw request and plan JSON</summary>
          <pre className="raw">{JSON.stringify(change, null, 2)}</pre>
          <pre className="raw">{JSON.stringify(plan, null, 2)}</pre>
        </details>
        <div className="plan-foot">
          <p className="hint">Sends exactly what is shown. A 409 asks for a new plan.</p>
          <span className="actions" style={{ marginTop: 0 }}>
            <button type="button" disabled={discardDisabled} onClick={onDiscard}>
              Discard plan
            </button>
            <button type="button" className="primary" disabled={applyDisabled} onClick={onApply}>
              Apply reviewed changes
            </button>
          </span>
        </div>
      </div>
    </section>
  );
}

type PendingReview = {
  change: ReviewedChange;
  plan: ConfigurationPlan;
  resolve: (ok: boolean) => void;
  opener: Element | null;
};

/**
 * usePlanReview opens PlanReview in a modal drawer and resolves true on
 * Apply, false on Discard, Escape, backdrop click or unmount. The caller
 * passes the opener it captured before its first await.
 */
export function usePlanReview(): [
  ReactNode,
  (change: ReviewedChange, plan: ConfigurationPlan, opener?: Element | null) => Promise<boolean>,
] {
  const [pending, setPending] = useState<PendingReview | null>(null);
  const pendingRef = useRef<PendingReview | null>(null);
  const pendingOpenerRef = useRef<Element | null>(null);
  // undefined: not decided yet. null: decided, and there is nothing to focus.
  const restoreRef = useRef<Element | null | undefined>(undefined);
  pendingRef.current = pending;
  // Do not clear this when pending becomes null. That render runs before the
  // drawer's passive cleanup, and the getter must still see the opener then.
  if (pending !== null) pendingOpenerRef.current = pending.opener;
  useEffect(() => () => pendingRef.current?.resolve(false), []);
  const review = useCallback((change: ReviewedChange, plan: ConfigurationPlan, opener?: Element | null) => {
    return new Promise<boolean>((resolve) => {
      pendingRef.current?.resolve(false);
      restoreRef.current = undefined;
      setPending({ change, plan, resolve, opener: opener === undefined ? document.activeElement : opener });
    });
  }, []);
  const close = useCallback((ok: boolean) => {
    const current = pendingRef.current;
    if (current === null) return;
    // Decide while the caller is still busy. Later re-enables cannot change this.
    restoreRef.current = focusTarget(current.opener);
    pendingRef.current = null;
    setPending(null);
    current.resolve(ok);
  }, []);
  const restoreTarget = () => (restoreRef.current !== undefined ? restoreRef.current : pendingOpenerRef.current);
  const node = pending === null ? null : <PlanDrawer pending={pending} onClose={close} restoreTarget={restoreTarget} />;
  return [node, review];
}

function PlanDrawer({
  pending,
  onClose,
  restoreTarget,
}: {
  pending: PendingReview;
  onClose: (ok: boolean) => void;
  restoreTarget: () => Element | null;
}) {
  const host = usePortalHost(true);
  useInertBackground(true, host, restoreTarget);
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (host !== null) ref.current?.querySelector<HTMLElement>("button")?.focus();
  }, [host]);
  if (host === null) return null;
  return createPortal(
    <div className="modal-backdrop drawer-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) { e.preventDefault(); onClose(false); } }}>
      <div
        ref={ref}
        className="drawer"
        role="dialog"
        tabIndex={-1}
        aria-modal="true"
        aria-label="Review planned change"
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.preventDefault();
            onClose(false);
          } else trapTab(e, ref.current);
        }}
      >
        <PlanReview
          change={pending.change}
          plan={pending.plan}
          title="Review planned change"
          // Status holds busyRef while the drawer is open, so the drawer is never busy-disabled;
          // close() settles the promise once, so a double click cannot apply twice.
          applyDisabled={false}
          discardDisabled={false}
          onApply={() => onClose(true)}
          onDiscard={() => onClose(false)}
        />
      </div>
    </div>,
    host,
  );
}
