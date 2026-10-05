import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, errorMessage, getState } from "../api/client";
import {
  applyConfiguration,
  configurationKey,
  exportConfigurationJSON,
  exportConfigurationYAMLDocument,
  planConfiguration,
  validateConfiguration,
  type ConfigurationExport,
  type ConfigurationOperation,
  type ConfigurationPlan,
  type ReviewedChange,
} from "../api/configuration";
import { useLiveSpec } from "../api/liveSpec";
import type { StateView } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_ADMIN } from "../auth/scopes";
import { useConfirm } from "../ui/ConfirmDialog";
import { DiffTable, PlanReview, PlanWarnings, RevisionChip } from "../ui/PlanReview";
import { ProblemBanner } from "../ui/ProblemBanner";
export const CONFIGURATION_OPERATIONS = [
  "replaceStoreCaps",
  "replaceAdmission",
  "replaceTLS",
  "replaceRules",
  "replaceTargets",
  "replaceCompat",
  "setFeature",
  "replaceHTTPAuth",
] as const;
const guidance: Record<string, string> = {
  replaceStoreCaps:
    "store: maxFlows, maxBytes, maxBodyBytes, fullPolicy (reject or evict_oldest). Byte sizes use IEC strings, for example 1MiB. Force permits shrink eviction.",
  replaceAdmission:
    "admission: maxSessions, maxSessionsPerIP, maxInFlight, maxInFlightBytes, maxConcurrentStreams, sessionTimeout, idleTimeout, headerTimeout, dialTimeout, upstreamTimeout. Durations use Go strings, for example 10s.",
  replaceTLS:
    "tls: intercept, hosts, ports, ca {mode, certFile, keyFile}, upstream {insecureSkipVerify, extraCAFiles}. File references only. Changing generate-mode TLS rotates the CA.",
  replaceRules:
    "rules: enabled and items. Each item supports id, enabled, phase, match and action; server validation is authoritative.",
  replaceTargets:
    "targets: denyCloudMetadata, denyLinkLocal, allowLoopback, allowHosts, denyHosts.",
  replaceCompat:
    "compat: flowREST {enabled, pathPrefix}; the nested flowREST object is required.",
  setFeature:
    "feature: id and enabled. Live IDs: protocols.http2, protocols.websocket, protocols.connect, protocols.absoluteForm, listeners.proxy.acceptSOCKS5, listeners.proxy.acceptSOCKS4, compat.flowREST, rules.enabled, ui.enabled. Disabling ui.enabled makes inspector routes unavailable; re-enable using REST/MCP or bootstrap and Reset.",
  replaceHTTPAuth:
    "httpAuth: enabled, realm, users [{id, usernameFile, passwordFile}]. Files contain credentials; never enter credential values here. Enabling requires at least one user.",
};
export function operationFromState(
  op: string,
  state: StateView,
): ConfigurationOperation {
  const spec = state.canonical?.spec as Record<string, unknown> | undefined;
  const proxy = spec?.proxy as Record<string, unknown> | undefined;
  const key = (
    {
      replaceStoreCaps: "store",
      replaceAdmission: "admission",
      replaceTLS: "tls",
      replaceRules: "rules",
      replaceTargets: "targets",
      replaceCompat: "compat",
      replaceHTTPAuth: "httpAuth",
    } as Record<string, string>
  )[op];
  if (op === "setFeature")
    return { op, feature: { id: "protocols.http2", enabled: false } };
  let value =
    key &&
    (["admission", "targets", "httpAuth"].includes(key)
      ? proxy?.[key]
      : spec?.[key]);
  if (op === "replaceStoreCaps" && value && typeof value === "object") {
    const store = value as Record<string, unknown>;
    value = {
      maxFlows: store.maxFlows,
      maxBytes: store.maxBytes,
      maxBodyBytes: store.maxBodyBytes,
      fullPolicy: store.fullPolicy,
    };
  }
  return { op, [key ?? ""]: value ?? {} };
}
const pretty = (value: unknown) => JSON.stringify(value, null, 2);
const subtree: Record<string, string> = {
  replaceStoreCaps: "store caps",
  replaceAdmission: "proxy.admission",
  replaceTLS: "tls",
  replaceRules: "rules",
  replaceTargets: "proxy.targets",
  replaceCompat: "compat.flowREST",
  setFeature: "one live feature ID",
  replaceHTTPAuth: "proxy.httpAuth",
};
type ConfigTab = "live" | "validate" | "export" | "state";
const TABS: { id: ConfigTab; label: string }[] = [
  { id: "live", label: "Live changes" },
  { id: "validate", label: "Validate candidate" },
  { id: "export", label: "Export" },
  { id: "state", label: "Current state" },
];
/** conflictLabel explains a 409 by its error code instead of assuming a revision change. */
function conflictLabel(code: string, automaticKey: boolean): string {
  switch (code) {
    case "revision_conflict":
      return "Runtime changed. Review your edits and plan again against the refreshed revision.";
    case "idempotency_conflict":
      return automaticKey
        ? "This idempotency key was already used for a different request. Plan again; a new automatic key will be used."
        : "This idempotency key was already used for a different request. Change the idempotency key, then plan again.";
    default:
      return `Conflict (${code}). Review the details above and plan again.`;
  }
}
export function ConfigurationPage() {
  const { hasScope } = useAuth();
  const canAdmin = hasScope(SCOPE_ADMIN);
  const { refresh: refreshLiveSpec } = useLiveSpec();
  const [state, setState] = useState<StateView | null>(null);
  const [tab, setTab] = useState<ConfigTab>("live");
  const [op, setOp] = useState<string>("replaceTLS");
  const [operations, setOperations] = useState("[]");
  const [candidate, setCandidate] = useState("{}");
  const [reason, setReason] = useState("");
  const [force, setForce] = useState(false);
  const [key, setKey] = useState("");
  const [automaticKey, setAutomaticKey] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [errorSuffix, setErrorSuffix] = useState("");
  const [result, setResult] = useState<ConfigurationPlan | null>(null);
  const [resultKind, setResultKind] = useState<"validate" | "candidate" | "candidate-ops" | "apply">("validate");
  const [validated, setValidated] = useState(false);
  const [review, setReview] = useState<{
    change: ReviewedChange;
    plan: ConfigurationPlan;
  } | null>(null);
  const [exported, setExported] = useState<ConfigurationExport | null>(null);
  const [exportBody, setExportBody] = useState("");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [renderConfirm, confirm] = useConfirm();
  async function load() {
    const fresh = await getState();
    setState(fresh);
    return fresh;
  }
  useEffect(() => {
    let cancelled = false;
    void getState()
      .then((fresh) => {
        if (cancelled) return;
        setState(fresh);
        setCandidate(pretty(fresh.canonical));
        setOperations(pretty([operationFromState("replaceTLS", fresh)]));
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(new Error(errorMessage(err, "Could not load state.", true)));
      });
    return () => {
      cancelled = true;
    };
  }, []);
  async function run(action: () => Promise<void>, requireAdmin = true) {
    if (busyRef.current || (requireAdmin && !canAdmin)) return;
    busyRef.current = true;
    setBusy(true);
    setError(null);
    setErrorSuffix("");
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err : new Error("Request failed."));
      if (err instanceof APIError && err.problem.status === 409) {
        setReview(null);
        if (automaticKey) setKey("");
        try {
          await load();
        } catch {
          /* Preserve conflict detail. */
        }
        setErrorSuffix(conflictLabel(err.problem.code, automaticKey));
      }
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }
  function parsedOperations(): ConfigurationOperation[] {
    const value: unknown = JSON.parse(operations);
    if (
      !Array.isArray(value) ||
      value.some(
        (row) => !row || typeof row !== "object" || typeof row.op !== "string",
      )
    )
      throw new Error("Operations must be a JSON array of objects with an op.");
    return value as ConfigurationOperation[];
  }
  function opCount(): number | null {
    try {
      const value: unknown = JSON.parse(operations);
      return Array.isArray(value) ? value.length : null;
    } catch {
      return null;
    }
  }
  function invalidate() {
    setReview(null);
    setResult(null);
    setValidated(false);
    if (automaticKey) setKey("");
  }
  function chooseTemplate(selected: string, append = false) {
    setOp(selected);
    if (state) {
      const next = operationFromState(selected, state);
      if (append) {
        let current: unknown[] = [];
        try {
          const value: unknown = JSON.parse(operations);
          if (Array.isArray(value)) current = value;
        } catch {
          /* Replace unparsable text with the template. */
        }
        setOperations(pretty([...current, next]));
      } else setOperations(pretty([next]));
    }
    invalidate();
  }
  async function applyReview() {
    if (!review) return;
    await run(async () => {
      const disablesUI = review.change.operations.some(
        (operation) =>
          operation.op === "setFeature" &&
          (operation.feature as { id?: string; enabled?: boolean } | undefined)?.id === "ui.enabled" &&
          (operation.feature as { enabled?: boolean }).enabled === false,
      );
      if (
        disablesUI &&
        !(await confirm({
          title: "Disable the inspector?",
          body: (
            <p>
              Disabling ui.enabled makes all inspector routes (/, /status, /flows/…) return 404. REST/MCP remain
              available. Re-enable using REST/MCP setFeature ui.enabled:true or edit bootstrap YAML and Reset.
            </p>
          ),
          confirmLabel: "Disable inspector",
          danger: true,
        }))
      )
        return;
      if (
        (review.plan.warnings?.some((warning) => warning.code === "store_evict") ||
          (review.change.force &&
            review.change.operations.some((operation) => operation.op === "replaceStoreCaps"))) &&
        !(await confirm({
          title: "Apply the reviewed store change?",
          body: <p>This store change may permanently evict captured flows.</p>,
          confirmLabel: "Apply and evict",
          danger: true,
        }))
      )
        return;
      const applied = await applyConfiguration(review.change);
      setResult(applied);
      setResultKind("apply");
      setReview(null);
      setKey("");
      setAutomaticKey(true);
      await load();
      await refreshLiveSpec();
    });
  }
  const disabled = !canAdmin || busy || !state;
  const count = opCount();
  const applied = resultKind === "apply" && result !== null;
  const steps: { label: string; state: "done" | "current" | "todo" }[] = [
    { label: "Edit", state: validated || review || applied ? "done" : "current" },
    // Only a successful "Validate operations" since the last edit marks Validate done; planning does not.
    { label: "Validate", state: validated ? "done" : "todo" },
    { label: "Review plan", state: applied ? "done" : review ? "current" : "todo" },
    { label: "Apply", state: applied ? "done" : "todo" },
  ];
  if (steps.every((s) => s.state !== "current") && !applied) {
    const firstTodo = steps.find((s) => s.state === "todo");
    if (firstTodo) firstTodo.state = "current";
  }
  return (
    <main className="page page--wide">
      <div className="page-head">
        <div>
          <p className="kicker">Control plane</p>
          <h1>Configuration</h1>
          <p className="sub">
            Live changes replace whole subtrees. Explicit empty strings and arrays are sent unchanged; omitted fields
            follow server defaults. Validate and review the plan before applying.
          </p>
        </div>
        <div className="page-head-actions">
          {state ? (
            <>
              <span className="hint">runtime</span>
              <RevisionChip rev={state.runtimeRevision} />
              <span className="hint">bootstrap</span>
              <RevisionChip rev={state.bootstrapRevision} />
              {state.drifted ? <span className="chip chip-warn">drifted</span> : null}
            </>
          ) : null}
          <button
            type="button"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                invalidate();
                await load();
              }, false)
            }
          >
            Refresh current state
          </button>
        </div>
      </div>
      <ProblemBanner error={error} fallback="Request failed." suffix={errorSuffix} />
      {!canAdmin && (
        <p className="banner-warn">
          Administrator scope is required for validation, export, planning and
          apply.
        </p>
      )}
      {result && (
        <section className="card" aria-label="Validation / apply result">
          <div className="card-b stack" role="status">
            <p className="note note-accent">
              <span className="mono">{applied ? "applied" : "valid"}</span>
              <span>
                {applied
                  ? `Applied · revision ${result.runtimeRevision ?? result.candidateRevision} · generation ${result.generation ?? "—"}`
                  : resultKind === "candidate"
                    ? "Candidate state valid."
                    : resultKind === "candidate-ops"
                      ? "Candidate state with operations valid."
                      : "Operations valid."}
              </span>
            </p>
            <DiffTable diff={result.diff} label={applied ? "Applied diff" : "Validated diff"} />
            <PlanWarnings plan={result} />
            <details>
              <summary>Complete {applied ? "apply" : "validation"} result JSON</summary>
              <pre className="raw">{pretty(result)}</pre>
            </details>
          </div>
        </section>
      )}
      <div className="tabs" role="tablist" aria-label="Configuration sections">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            id={`config-tab-${t.id}`}
            aria-controls={`config-panel-${t.id}`}
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <section role="tabpanel" id="config-panel-live" aria-labelledby="config-tab-live" hidden={tab !== "live"}>
        <div className="config-grid">
          <div className="card">
            <div className="card-h">
              <h2>Operation templates</h2>
              <span className="chip">{CONFIGURATION_OPERATIONS.length}</span>
            </div>
            <div className="card-b">
              <div className="template-list" role="group" aria-label="Operation template">
                {CONFIGURATION_OPERATIONS.map((name) => (
                  <button
                    key={name}
                    type="button"
                    aria-pressed={op === name}
                    disabled={disabled}
                    onClick={() => chooseTemplate(name)}
                  >
                    <span className="op">{name}</span>{" "}
                    <span className="hint">{subtree[name]}</span>
                  </button>
                ))}
              </div>
              <p className="hint" style={{ marginTop: "0.75rem" }}>
                Listener addresses, management TLS, metrics.listen, originalDestination, SOCKS BIND/UDP/user-pass and
                HTTP/2 1.2 flags and WebSocket frame inspection require editing bootstrap YAML and{" "}
                <Link to="/reset">Reset</Link>. Reset rereads bootstrap and wipes flows. This page never writes
                bootstrap.
              </p>
            </div>
          </div>
          <div className="stack">
            <ol className="stepper" aria-label="Change steps">
              {steps.map((st, i) => (
                <li key={st.label} data-state={st.state} aria-current={st.state === "current" ? "step" : undefined}>
                  <span className="step-n">{st.state === "done" ? "✓" : i + 1}</span>
                  {st.label}
                </li>
              ))}
            </ol>
            <div className="card">
              <div className="card-h">
                <h2>
                  Operations JSON · {count === null ? "invalid JSON" : `${count} op${count === 1 ? "" : "s"}`}
                </h2>
                <span className="actions" style={{ marginTop: 0 }}>
                  <button type="button" className="btn-sm" disabled={disabled} onClick={() => chooseTemplate(op)}>
                    Reset to current
                  </button>
                  <button type="button" className="btn-sm" disabled={disabled} onClick={() => chooseTemplate(op, true)}>
                    Add op
                  </button>
                </span>
              </div>
              <div className="card-b stack">
                <div className="field">
                  <label htmlFor="configuration-operations" className="visually-hidden">
                    Operations JSON
                  </label>
                  <textarea
                    id="configuration-operations"
                    rows={16}
                    value={operations}
                    disabled={disabled}
                    spellCheck={false}
                    onChange={(event) => {
                      setOperations(event.target.value);
                      invalidate();
                    }}
                  />
                </div>
                <p className="hint">{guidance[op]}</p>
                <p className="hint">
                  <Link to="/diagnostics">Local configuration schema and API diagnostics</Link>. Edit every field in
                  the selected subtree; add operations to the array to apply several changes atomically.
                </p>
                <div className="field">
                  <label htmlFor="configuration-reason">Reason (optional)</label>
                  <input
                    id="configuration-reason"
                    value={reason}
                    disabled={disabled}
                    onChange={(event) => {
                      setReason(event.target.value);
                      invalidate();
                    }}
                  />
                </div>
                <div className="field">
                  <label htmlFor="configuration-key">Idempotency key (optional; generated for plan)</label>
                  <input
                    id="configuration-key"
                    value={key}
                    disabled={disabled}
                    onChange={(event) => {
                      setKey(event.target.value);
                      setAutomaticKey(event.target.value === "");
                      setReview(null);
                      setResult(null);
                      setValidated(false);
                    }}
                  />
                </div>
                <label className="danger-text">
                  <input
                    type="checkbox"
                    checked={force}
                    disabled={disabled}
                    onChange={(event) => {
                      setForce(event.target.checked);
                      invalidate();
                    }}
                  />{" "}
                  Force store shrink eviction
                </label>
                <div className="actions">
                  <button
                    type="button"
                    disabled={disabled}
                    onClick={() =>
                      void run(async () => {
                        setResult(null);
                        const validation = await validateConfiguration({
                          operations: parsedOperations(),
                        });
                        setResult(validation);
                        setResultKind("validate");
                        setValidated(true);
                      })
                    }
                  >
                    Validate operations
                  </button>
                  <button
                    type="button"
                    className="primary"
                    disabled={disabled}
                    onClick={() =>
                      void run(async () => {
                        setReview(null);
                        setResult(null);
                        const change: ReviewedChange = {
                          expectedRevision: state!.runtimeRevision,
                          idempotencyKey: key || configurationKey(),
                          reason,
                          force,
                          operations: parsedOperations(),
                        };
                        const plan = await planConfiguration(change);
                        if (plan.previousRevision !== change.expectedRevision)
                          throw new Error(
                            "This idempotency key returned a plan for a different revision. Choose a new key and plan again.",
                          );
                        setKey(change.idempotencyKey);
                        setReview({ change, plan });
                      })
                    }
                  >
                    Plan changes
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div>
            {review ? (
              <PlanReview
                change={review.change}
                plan={review.plan}
                applyDisabled={disabled}
                discardDisabled={busy}
                headingId="configuration-review-heading"
                onApply={() => void applyReview()}
                onDiscard={() => {
                  setReview(null);
                  if (automaticKey) setKey("");
                }}
              />
            ) : (
              <div className="card">
                <div className="empty-state">
                  <p className="empty-title">No plan yet</p>
                  <p>Plan changes to review the diff here.</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </section>
      <section
        role="tabpanel"
        id="config-panel-validate"
        aria-labelledby="config-tab-validate"
        hidden={tab !== "validate"}
        className="card"
      >
        <div className="card-b stack">
          <p className="hint">
            Validate the complete canonical JSON document, including bootstrap-only fields. Validation does not apply
            or save it.
          </p>
          <div className="field">
            <label htmlFor="configuration-candidate">Candidate state JSON</label>
            <textarea
              id="configuration-candidate"
              rows={16}
              value={candidate}
              disabled={disabled}
              spellCheck={false}
              onChange={(event) => {
                setCandidate(event.target.value);
                setResult(null);
              }}
            />
          </div>
          <div className="actions">
            <button
              type="button"
              disabled={disabled}
              onClick={() =>
                void run(async () => {
                  setResult(null);
                  setResult(
                    await validateConfiguration({
                      state: JSON.parse(candidate) as unknown,
                    }),
                  );
                  setResultKind("candidate");
                })
              }
            >
              Validate candidate state
            </button>
            <button
              type="button"
              disabled={disabled}
              onClick={() =>
                void run(async () => {
                  setResult(null);
                  setResult(
                    await validateConfiguration({
                      state: JSON.parse(candidate) as unknown,
                      operations: parsedOperations(),
                    }),
                  );
                  setResultKind("candidate-ops");
                })
              }
            >
              Validate candidate with operations
            </button>
            <span className="hint">
              {count === null ? "Operations JSON on Live changes is invalid." : `${count} op${count === 1 ? "" : "s"} from Live changes`}
            </span>
          </div>
        </div>
      </section>
      <section
        role="tabpanel"
        id="config-panel-export"
        aria-labelledby="config-tab-export"
        hidden={tab !== "export"}
        className="card"
      >
        <div className="card-b stack">
          <p className="hint">
            Export is canonical runtime desired state with file references. Review drift before updating your bootstrap
            outside the inspector.
          </p>
          <div className="actions">
            {(["JSON", "YAML"] as const).map((format) => (
              <button
                key={format}
                type="button"
                disabled={disabled}
                onClick={() =>
                  void run(async () => {
                    setExported(null);
                    setExportBody("");
                    const metadata = await exportConfigurationJSON();
                    if (format === "YAML") {
                      const yaml = await exportConfigurationYAMLDocument();
                      if (yaml.revision !== metadata.revision)
                        throw new Error("Runtime changed during export. Export again.");
                      setExportBody(yaml.body);
                    } else setExportBody(pretty(metadata.body));
                    setExported(metadata);
                  })
                }
              >
                Export {format}
              </button>
            ))}
          </div>
          {exported && (
            <>
              <dl className="kv">
                <div>
                  <dt>Runtime revision</dt>
                  <dd>{exported.revision}</dd>
                </div>
                <div>
                  <dt>Bootstrap revision</dt>
                  <dd>{exported.bootstrapRevision}</dd>
                </div>
                <div>
                  <dt>Drifted</dt>
                  <dd>{String(exported.drifted)}</dd>
                </div>
              </dl>
              <pre className="raw">{exported.humanDiff || "No bootstrap drift."}</pre>
              <textarea aria-label="Canonical export document" rows={16} readOnly value={exportBody} />
            </>
          )}
        </div>
      </section>
      <section
        role="tabpanel"
        id="config-panel-state"
        aria-labelledby="config-tab-state"
        hidden={tab !== "state"}
        className="card"
      >
        <div className="card-b stack">
          {state ? (
            <dl className="kv">
              <div>
                <dt>Runtime revision</dt>
                <dd>{state.runtimeRevision}</dd>
              </div>
              <div>
                <dt>Bootstrap revision</dt>
                <dd>{state.bootstrapRevision ?? "—"}</dd>
              </div>
              <div>
                <dt>Generation</dt>
                <dd>{state.generation ?? "—"}</dd>
              </div>
              <div>
                <dt>Drifted</dt>
                <dd>{String(state.drifted ?? false)}</dd>
              </div>
            </dl>
          ) : (
            <p className="muted">Loading state…</p>
          )}
          <details>
            <summary>Complete canonical state and revisions</summary>
            <pre className="raw">{pretty(state)}</pre>
          </details>
        </div>
      </section>
      {renderConfirm()}
    </main>
  );
}
