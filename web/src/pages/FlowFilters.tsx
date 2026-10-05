import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import { errorMessage, waitFlow } from "../api/client";
import { useLiveSpec } from "../api/liveSpec";
import type { FlowListQuery, WaitFilter } from "../api/types";
import { FOCUSABLE } from "../ui/ConfirmDialog";

const shared = [
  "host",
  "method",
  "status",
  "pathPrefix",
  "protocol",
  "via",
] as const;

type FilterKey = (typeof shared)[number] | "scheme" | "ruleId" | "intercepted";
const listKeys: readonly FilterKey[] = [...shared, "scheme", "ruleId", "intercepted"];

const fields: { key: (typeof shared)[number] | "scheme" | "ruleId"; label: string; placeholder: string; listOnly?: boolean }[] = [
  { key: "host", label: "Host", placeholder: "shop.lab" },
  { key: "method", label: "Method", placeholder: "POST" },
  { key: "status", label: "Status", placeholder: "e.g. 502" },
  { key: "pathPrefix", label: "Path prefix", placeholder: "/checkout" },
  { key: "protocol", label: "Protocol", placeholder: "http/1.1" },
  { key: "via", label: "Transport", placeholder: "http · socks5 · originalDest" },
  { key: "scheme", label: "Scheme", placeholder: "http / https", listOnly: true },
  { key: "ruleId", label: "Rule ID", placeholder: "rule id", listOnly: true },
];

/** goDurationMs parses Go durations built from h/m/s/ms/us/ns units; null when unparsable. */
export function goDurationMs(text: string): number | null {
  const s = text.trim();
  if (!/^(\d+(\.\d+)?(h|m|s|ms|us|µs|ns))+$/.test(s)) return null;
  const unit: Record<string, number> = { h: 3_600_000, m: 60_000, s: 1000, ms: 1, us: 0.001, "µs": 0.001, ns: 0.000001 };
  let total = 0;
  for (const m of s.matchAll(/(\d+(?:\.\d+)?)(h|ms|m|s|us|µs|ns)/g)) total += Number(m[1]) * (unit[m[2] ?? ""] ?? 0);
  return total > 0 ? total : null;
}

type RuleOption = { id: string; label: string };

function ruleOptions(rules: unknown[] | undefined): RuleOption[] {
  const out: RuleOption[] = [];
  for (const raw of rules ?? []) {
    if (raw === null || typeof raw !== "object") continue;
    const r = raw as { id?: unknown; phase?: unknown; action?: { type?: unknown } };
    if (typeof r.id !== "string" || r.id === "") continue;
    const parts = [r.action?.type, r.phase].filter((p): p is string => typeof p === "string" && p !== "");
    out.push({ id: r.id, label: parts.join(" · ") });
  }
  return out;
}

function chipLabel(key: string, value: string): string {
  if (key === "intercepted") return value === "true" ? "intercepted" : "not intercepted";
  return `${key}: ${value}`;
}

export function FlowFilters({
  onFilter,
  triggerHost = null,
  popoverHost = null,
}: {
  onFilter: (query: FlowListQuery) => void;
  /** Where the "Filters & wait" trigger renders (inline when null). */
  triggerHost?: HTMLElement | null;
  /** Where the popover renders (inline when null); it is only hidden when closed, never unmounted. */
  popoverHost?: HTMLElement | null;
}) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [applied, setApplied] = useState<FlowListQuery>({});
  const [open, setOpen] = useState(false);
  // The form renders after the first open and then stays mounted (hidden when closed).
  const [opened, setOpened] = useState(false);
  const [timeout, setTimeout] = useState("30s");
  const [waiting, setWaiting] = useState(false);
  const [waitStarted, setWaitStarted] = useState(0);
  const [waitTimeout, setWaitTimeout] = useState("");
  const [now, setNow] = useState(0);
  const [message, setMessage] = useState("");
  const controller = useRef<AbortController | null>(null);
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const navigate = useNavigate();
  const ids = useId();
  const { state } = useLiveSpec();
  const rules = ruleOptions(state?.canonical?.spec?.rules?.items);
  // Abort only when the whole component unmounts; closing the popover only hides it.
  useEffect(() => () => controller.current?.abort(), []);

  useEffect(() => {
    if (!waiting) return;
    const t = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(t);
  }, [waiting]);

  // Opening moves focus into the popover (first field); Escape/close returns it to the trigger.
  // Runs only on the closed -> open transition, so re-renders while open never steal focus.
  useEffect(() => {
    if (!open) return;
    const first = document.getElementById(`${ids}-${fields[0]!.key}`);
    (first ?? popoverRef.current)?.focus();
  }, [open, ids]);

  useEffect(() => {
    if (!open) return;
    function onDown(event: MouseEvent) {
      const target = event.target as Node | null;
      if (target === null) return;
      if (popoverRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      setOpen(false);
      const el = target instanceof Element ? target : null;
      if (el?.closest(FOCUSABLE) == null) {
        // Defer past the completing click so non-focusable targets (body) do not leave focus on body.
        const trigger = triggerRef.current;
        queueMicrotask(() => trigger?.focus());
      }
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [open]);

  async function wait() {
    if (
      values.status &&
      (!/^\d+$/.test(values.status) ||
        !Number.isSafeInteger(Number(values.status)))
    ) {
      setMessage("Status must be a non-negative integer.");
      return;
    }
    const current = new AbortController();
    controller.current = current;
    setWaiting(true);
    setWaitStarted(Date.now());
    setWaitTimeout(timeout.trim());
    setNow(Date.now());
    setMessage("");
    const filter: WaitFilter = {};
    for (const key of shared) {
      if (values[key]) {
        Object.assign(filter, {
          [key]: key === "status" ? Number(values[key]) : values[key],
        });
      }
    }
    if (values.intercepted) filter.intercepted = values.intercepted === "true";
    if (values.after) filter.after = values.after;
    try {
      const flow = await waitFlow(filter, timeout, current.signal);
      if (!current.signal.aborted) {
        setMessage(`Matched flow ${flow.id}`);
        navigate(`/flows/${encodeURIComponent(flow.id)}`);
      }
    } catch (err) {
      if (!current.signal.aborted) {
        setMessage(errorMessage(err, "Wait failed.", true));
      }
    } finally {
      if (controller.current === current) {
        controller.current = null;
        setWaiting(false);
      }
    }
  }

  function cancelWait() {
    controller.current?.abort();
    setWaiting(false);
    setMessage("Wait cancelled.");
  }

  function apply(next: Record<string, string>) {
    const query: FlowListQuery = {};
    for (const key of listKeys) {
      if (next[key]) query[key] = next[key];
    }
    setApplied(query);
    onFilter(query);
  }

  // Removing a chip re-applies the *applied* filters minus that key (never unapplied form edits),
  // and clears the same key in the form.
  function removeApplied(key: FilterKey | "all") {
    const nextValues = { ...values };
    const nextApplied: Record<string, string> = {};
    const current = applied as Record<string, string | undefined>;
    for (const k of listKeys) {
      const v = current[k];
      if (v) nextApplied[k] = v;
    }
    const removed = key === "all" ? listKeys : [key];
    for (const k of removed) {
      delete nextValues[k];
      delete nextApplied[k];
    }
    setValues(nextValues);
    apply(nextApplied);
  }

  function close() {
    setOpen(false);
    triggerRef.current?.focus();
  }

  const appliedKeys = Object.keys(applied) as FilterKey[];
  const totalMs = goDurationMs(waitTimeout);
  const elapsedMs = Math.max(0, now - waitStarted);
  const pct = totalMs === null ? null : Math.min(100, (elapsedMs / totalMs) * 100);
  const waitLabel = `Waiting · ${Math.floor(elapsedMs / 1000)}s${totalMs === null ? "" : ` of ${waitTimeout}`}`;
  const progress = waiting ? (
    <div
      className={`progress${pct === null ? " progress-indeterminate" : ""}`}
      role="progressbar"
      aria-label="Wait progress"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct === null ? undefined : Math.round(pct)}
    >
      <span style={pct === null ? undefined : { width: `${pct}%` }} />
    </div>
  ) : null;

  const trigger = (
    <button
      type="button"
      ref={triggerRef}
      className={`btn-sm${appliedKeys.length > 0 ? " chip-accent" : ""}`}
      aria-expanded={open}
      aria-controls={`${ids}-popover`}
      onClick={() => {
        setOpened(true);
        setOpen(!open);
      }}
    >
      Filters &amp; wait{appliedKeys.length > 0 ? ` · ${appliedKeys.length}` : ""}
    </button>
  );

  // The wait outcome has exactly one status region: inside the popover while it is open,
  // in the list head while it is hidden (moved, never duplicated).
  const messageEl = message ? (
    <div className="wait-message-row list-head-row">
      <p role="status" className="hint wait-message">
        {message}
      </p>
      <button type="button" className="btn-sm" onClick={() => setMessage("")}>
        Dismiss
      </button>
    </div>
  ) : null;

  const popover = (
    <div
      ref={popoverRef}
      id={`${ids}-popover`}
      className="popover"
      role="dialog"
      aria-label="Server filters and wait"
      tabIndex={-1}
      hidden={!open}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          close();
        }
      }}
    >
      {opened ? (
        <>
      <div className="card-h">
        <h2>Server filters</h2>
        <span className="hint">GET /v1/flows · every cursor page is loaded</span>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          apply(values);
        }}
      >
        <div className="card-b popover-grid">
          {fields.map(({ key, label, placeholder, listOnly }) => (
            <div className="field" key={key}>
              <label htmlFor={`${ids}-${key}`}>
                {label} <code>{key}</code>
                {listOnly ? (
                  <>
                    {" "}
                    <span className="chip chip-warn">list only</span>
                  </>
                ) : null}
              </label>
              <input
                id={`${ids}-${key}`}
                placeholder={placeholder}
                list={key === "ruleId" && rules.length > 0 ? `${ids}-rules` : undefined}
                value={values[key] || ""}
                onChange={(event) =>
                  setValues({ ...values, [key]: event.target.value })
                }
              />
            </div>
          ))}
          {rules.length > 0 ? (
            <datalist id={`${ids}-rules`}>
              {rules.map((r) => (
                <option key={r.id} value={r.id} label={r.label || undefined} />
              ))}
            </datalist>
          ) : null}
          <fieldset className="field" style={{ border: 0, padding: 0, margin: 0 }}>
            <legend className="hint">
              Intercepted <code>intercepted</code>
            </legend>
            <div className="seg" role="radiogroup" aria-label="Intercepted filter">
              {[
                ["", "Any"],
                ["true", "Intercepted"],
                ["false", "Not intercepted"],
              ].map(([value = "", label]) => (
                <label key={value || "any"}>
                  <input
                    type="radio"
                    name={`${ids}-intercepted`}
                    value={value}
                    checked={(values.intercepted || "") === value}
                    onChange={() => setValues({ ...values, intercepted: value })}
                  />
                  {label}
                </label>
              ))}
            </div>
          </fieldset>
        </div>
        <section className="popover-section" aria-label="Wait for next match">
          <div className="list-head-row">
            <h2 className="kicker">Wait for next match</h2>
            <span className="hint">
              Uses host, method, status, pathPrefix, protocol, via, intercepted and after. Scheme and ruleId apply to
              the list only.
            </span>
          </div>
          <div className="row">
            <div className="field" style={{ flex: 2 }}>
              <label htmlFor={`${ids}-after`}>Wait after (RFC3339)</label>
              <div className="inline-field">
                <input
                  id={`${ids}-after`}
                  placeholder="2026-10-03T21:52:00Z"
                  value={values.after || ""}
                  onChange={(event) =>
                    setValues({ ...values, after: event.target.value })
                  }
                />
                <button
                  type="button"
                  className="btn-sm"
                  onClick={() => setValues({ ...values, after: new Date().toISOString() })}
                >
                  Now
                </button>
              </div>
            </div>
            <div className="field" style={{ flex: 1 }}>
              <label htmlFor={`${ids}-timeout`}>Wait timeout (Go duration)</label>
              <input
                id={`${ids}-timeout`}
                value={timeout}
                onChange={(event) => setTimeout(event.target.value)}
              />
            </div>
            {waiting ? (
              <button type="button" onClick={cancelWait}>
                Cancel wait
              </button>
            ) : (
              <button type="button" onClick={() => void wait()}>
                Wait for flow
              </button>
            )}
          </div>
          {open && progress ? <div style={{ marginTop: "0.5rem" }}>{progress}</div> : null}
          {open ? messageEl : null}
          {open && waiting ? (
            <p className="hint">
              <span className="chip-accent">{waitLabel}</span> — a match opens in the inspector. A timeout shows here
              and keeps your filters.
            </p>
          ) : null}
        </section>
        <div className="popover-section popover-foot">
          <span className="hint">Search box narrows loaded rows locally; these query the server.</span>
          <span className="actions" style={{ marginTop: 0 }}>
            <button
              type="button"
              onClick={() => {
                const next = { ...values };
                for (const k of listKeys) delete next[k];
                setValues(next);
              }}
            >
              Reset
            </button>
            <button type="submit">Apply filters</button>
          </span>
        </div>
      </form>
        </>
      ) : null}
    </div>
  );

  const inline: ReactNode[] = [];
  if (appliedKeys.length > 0) {
    inline.push(
      <div className="chip-row" key="chips" aria-label="Active server filters" role="group">
        <span className="hint">Server filters</span>
        {appliedKeys.map((key) => (
          <button
            type="button"
            key={key}
            className="chip chip-accent"
            aria-label={`Remove filter ${chipLabel(key, applied[key] ?? "")}`}
            onClick={() => removeApplied(key)}
          >
            {chipLabel(key, applied[key] ?? "")} <span aria-hidden="true">×</span>
          </button>
        ))}
        <button type="button" className="chip" onClick={() => removeApplied("all")}>
          Clear filters
        </button>
      </div>,
    );
  }
  if (waiting && !open) {
    inline.push(
      <div className="wait-strip" key="wait">
        <div className="list-head-row">
          <span className="hint">{waitLabel}</span>
          <button type="button" className="btn-sm" onClick={cancelWait}>
            Cancel wait
          </button>
        </div>
        {progress}
      </div>,
    );
  }

  return (
    <>
      {triggerHost ? createPortal(trigger, triggerHost) : trigger}
      {popoverHost ? createPortal(popover, popoverHost) : popover}
      {inline}
      {!open ? messageEl : null}
    </>
  );
}
