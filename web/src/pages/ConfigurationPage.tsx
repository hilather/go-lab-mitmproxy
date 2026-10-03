import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, getState } from "../api/client";
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
export function ConfigurationPage() {
  const { hasScope } = useAuth();
  const canAdmin = hasScope(SCOPE_ADMIN);
  const { refresh: refreshLiveSpec } = useLiveSpec();
  const [state, setState] = useState<StateView | null>(null);
  const [op, setOp] = useState<string>("replaceTLS");
  const [operations, setOperations] = useState("[]");
  const [candidate, setCandidate] = useState("{}");
  const [reason, setReason] = useState("");
  const [force, setForce] = useState(false);
  const [key, setKey] = useState("");
  const [automaticKey, setAutomaticKey] = useState(true);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ConfigurationPlan | null>(null);
  const [review, setReview] = useState<{
    change: ReviewedChange;
    plan: ConfigurationPlan;
  } | null>(null);
  const [exported, setExported] = useState<ConfigurationExport | null>(null);
  const [exportBody, setExportBody] = useState("");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
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
          setError(
            err instanceof Error ? err.message : "Could not load state.",
          );
      });
    return () => {
      cancelled = true;
    };
  }, []);
  async function run(action: () => Promise<void>, requireAdmin = true) {
    if (busyRef.current || (requireAdmin && !canAdmin)) return;
    busyRef.current = true;
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (err) {
      setError(
        err instanceof APIError
          ? pretty(err.problem)
          : err instanceof Error
            ? err.message
            : "Request failed.",
      );
      if (err instanceof APIError && err.problem.status === 409) {
        setReview(null);
        if (automaticKey) setKey("");
        try {
          await load();
        } catch {
          /* Preserve conflict detail. */
        }
        setError(
          `${pretty(err.problem)}\nRuntime changed. Review your edits and plan again against the refreshed revision.`,
        );
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
  function invalidate() {
    setReview(null);
    setResult(null);
    if (automaticKey) setKey("");
  }
  return (
    <main className="page">
      <p className="kicker">Configuration</p>
      <h1>Configuration</h1>
      <p>
        Live changes replace whole subtrees. Explicit empty strings and arrays
        are sent unchanged; omitted fields follow server defaults. Validate and
        review the plan before applying.
      </p>
      <p>
        Listener addresses, management TLS, metrics.listen, originalDestination,
        SOCKS BIND/UDP/user-pass and HTTP/2 1.2 flags and WebSocket frame
        inspection require editing bootstrap YAML and{" "}
        <Link to="/reset">Reset</Link>. Reset rereads bootstrap and wipes flows.
        This page never writes bootstrap.
      </p>
      {error && (
        <pre className="banner-error" role="alert">
          {error}
        </pre>
      )}
      {!canAdmin && (
        <p className="banner-warn">
          Administrator scope is required for validation, export, planning and
          apply.
        </p>
      )}
      <section className="panel">
        <h2>Current state</h2>
        <button
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
        <details>
          <summary>Complete canonical state and revisions</summary>
          <pre className="raw">{pretty(state)}</pre>
        </details>
      </section>
      <section className="panel">
        <h2>Live changes</h2>
        <label htmlFor="configuration-operation">Operation template</label>{" "}
        <select
          id="configuration-operation"
          value={op}
          disabled={!canAdmin || busy || !state}
          onChange={(event) => {
            const selected = event.target.value;
            setOp(selected);
            if (state)
              setOperations(pretty([operationFromState(selected, state)]));
            invalidate();
          }}
        >
          {CONFIGURATION_OPERATIONS.map((name) => (
            <option key={name}>{name}</option>
          ))}
        </select>
        <p>{guidance[op]}</p>
        <p>
          <Link to="/diagnostics">
            Local configuration schema and API diagnostics
          </Link>
          . Edit every field in the selected subtree; add operations to the
          array to apply several changes atomically.
        </p>
        <div className="field">
          <label htmlFor="configuration-operations">Operations JSON</label>
          <textarea
            id="configuration-operations"
            rows={18}
            value={operations}
            disabled={!canAdmin || busy || !state}
            spellCheck={false}
            onChange={(event) => {
              setOperations(event.target.value);
              invalidate();
            }}
          />
        </div>
        <div className="field">
          <label htmlFor="configuration-reason">Reason (optional)</label>
          <input
            id="configuration-reason"
            value={reason}
            disabled={!canAdmin || busy || !state}
            onChange={(event) => {
              setReason(event.target.value);
              invalidate();
            }}
          />
        </div>
        <div className="field">
          <label htmlFor="configuration-key">
            Idempotency key (optional; generated for plan)
          </label>
          <input
            id="configuration-key"
            value={key}
            disabled={!canAdmin || busy || !state}
            onChange={(event) => {
              setKey(event.target.value);
              setAutomaticKey(event.target.value === "");
              setReview(null);
              setResult(null);
            }}
          />
        </div>
        <label>
          <input
            type="checkbox"
            checked={force}
            disabled={!canAdmin || busy || !state}
            onChange={(event) => {
              setForce(event.target.checked);
              invalidate();
            }}
          />{" "}
          Force store shrink eviction
        </label>
        <div className="actions">
          <button
            disabled={!canAdmin || busy || !state}
            onClick={() =>
              void run(async () => {
                setResult(null);
                setResult(
                  await validateConfiguration({
                    operations: parsedOperations(),
                  }),
                );
              })
            }
          >
            Validate operations
          </button>
          <button
            disabled={!canAdmin || busy || !state}
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
      </section>
      {review && (
        <section className="panel">
          <h2>Review planned changes</h2>
          <p>
            Apply sends this exact revision, idempotency key, reason, force and
            payload. Concurrent changes require a fresh plan.
          </p>
          <pre className="raw">{pretty(review.change)}</pre>
          <pre className="raw">{pretty(review.plan)}</pre>
          <button
            disabled={!canAdmin || busy || !state}
            onClick={() =>
              void run(async () => {
                const disablesUI = review.change.operations.some(
                  (operation) =>
                    operation.op === "setFeature" &&
                    (
                      operation.feature as
                        | {
                            id?: string;
                            enabled?: boolean;
                          }
                        | undefined
                    )?.id === "ui.enabled" &&
                    (
                      operation.feature as {
                        enabled?: boolean;
                      }
                    ).enabled === false,
                );
                if (
                  disablesUI &&
                  !window.confirm(
                    "Disabling ui.enabled makes all inspector routes return 404. REST/MCP remain available. Re-enable using REST/MCP setFeature ui.enabled:true or edit bootstrap YAML and Reset. Disable the inspector?",
                  )
                )
                  return;
                if (
                  (review.plan.warnings?.some(
                    (warning) => warning.code === "store_evict",
                  ) ||
                    (review.change.force &&
                      review.change.operations.some(
                        (operation) => operation.op === "replaceStoreCaps",
                      ))) &&
                  !window.confirm(
                    "This store change may permanently evict captured flows. Apply the reviewed store change?",
                  )
                )
                  return;
                const applied = await applyConfiguration(review.change);
                setResult(applied);
                setReview(null);
                setKey("");
                setAutomaticKey(true);
                await load();
                await refreshLiveSpec();
              })
            }
          >
            Apply reviewed changes
          </button>
          <button
            disabled={busy}
            onClick={() => {
              setReview(null);
              if (automaticKey) setKey("");
            }}
          >
            Discard plan
          </button>
        </section>
      )}
      <section className="panel">
        <h2>Candidate state validation</h2>
        <p>
          Validate the complete canonical JSON document, including
          bootstrap-only fields. Validation does not apply or save it.
        </p>
        <div className="field">
          <label htmlFor="configuration-candidate">Candidate state JSON</label>
          <textarea
            id="configuration-candidate"
            rows={16}
            value={candidate}
            disabled={!canAdmin || busy || !state}
            spellCheck={false}
            onChange={(event) => {
              setCandidate(event.target.value);
              setResult(null);
            }}
          />
        </div>
        <button
          disabled={!canAdmin || busy || !state}
          onClick={() =>
            void run(async () => {
              setResult(null);
              setResult(
                await validateConfiguration({
                  state: JSON.parse(candidate) as unknown,
                }),
              );
            })
          }
        >
          Validate candidate state
        </button>
        <button
          disabled={!canAdmin || busy || !state}
          onClick={() =>
            void run(async () => {
              setResult(null);
              setResult(
                await validateConfiguration({
                  state: JSON.parse(candidate) as unknown,
                  operations: parsedOperations(),
                }),
              );
            })
          }
        >
          Validate candidate with operations
        </button>
      </section>
      {result && (
        <section className="panel">
          <h2>Validation / apply result</h2>
          <pre className="raw" role="status">
            {pretty(result)}
          </pre>
        </section>
      )}
      <section className="panel">
        <h2>Canonical export</h2>
        <p>
          Export is canonical runtime desired state with file references. Review
          drift before updating your bootstrap outside the inspector.
        </p>
        {(["JSON", "YAML"] as const).map((format) => (
          <button
            key={format}
            disabled={!canAdmin || busy || !state}
            onClick={() =>
              void run(async () => {
                setExported(null);
                setExportBody("");
                const metadata = await exportConfigurationJSON();
                if (format === "YAML") {
                  const yaml = await exportConfigurationYAMLDocument();
                  if (yaml.revision !== metadata.revision)
                    throw new Error(
                      "Runtime changed during export. Export again.",
                    );
                  setExportBody(yaml.body);
                } else setExportBody(pretty(metadata.body));
                setExported(metadata);
              })
            }
          >
            Export {format}
          </button>
        ))}
        {exported && (
          <>
            <dl>
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
            <pre className="raw">
              {exported.humanDiff || "No bootstrap drift."}
            </pre>
            <textarea
              aria-label="Canonical export document"
              rows={16}
              readOnly
              value={exportBody}
            />
          </>
        )}
      </section>
    </main>
  );
}
