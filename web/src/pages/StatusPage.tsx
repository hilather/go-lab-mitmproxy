import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { APIError, applyChanges, CA_DOWNLOAD_URL, getFeatures, getState, getStatus } from "../api/client";
import { useLiveSpec } from "../api/liveSpec";
import type {
  AdmissionSpec,
  ChangeOperation,
  Feature,
  FeatureList,
  HTTPAuthSpec,
  HTTPAuthUser,
  StateView,
  Status,
  TLSSpec,
} from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_ADMIN, formatBytes } from "../auth/scopes";

const FEATURE_UI_ENABLED = "ui.enabled";
const FEATURE_RULES_ENABLED = "rules.enabled";
const FEATURE_COMPAT = "compat.flowREST";

const RESET_ONLY_FLAGS: { key: keyof Status["features"]; label: string }[] = [
  { key: "http2ClientCleartext", label: "http2ClientCleartext" },
  { key: "http2Origin", label: "http2Origin" },
  { key: "http2ExtendedConnect", label: "http2ExtendedConnect" },
  { key: "http2CapturePush", label: "http2CapturePush" },
  { key: "http2GRPCDecode", label: "http2GRPCDecode" },
  { key: "inspectWebSocketFrames", label: "inspectWebSocketFrames" },
  { key: "acceptBind", label: "acceptBind" },
  { key: "acceptUDPAssociate", label: "acceptUDPAssociate" },
  { key: "acceptUserPass", label: "acceptUserPass" },
  { key: "originalDestination", label: "originalDestination" },
];

const UI_OFF_CONFIRM =
  "Disabling ui.enabled 404s all inspector routes (/, /status, /flows/…). REST/MCP stay up. Re-enable with REST/MCP setFeature ui.enabled: true or bootstrap YAML and Reset. Continue?";

function featureToggleable(feature: Feature, isAdmin: boolean): boolean {
  return isAdmin && feature.applyMode === "live" && feature.verb === "setFeature";
}

function parsePorts(raw: string): number[] | string {
  const parts = raw
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "");
  if (parts.length === 0) {
    return "ports are required";
  }
  const ports: number[] = [];
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      return "tls.ports entries must be 1–65535";
    }
    ports.push(n);
  }
  return ports;
}

export function StatusPage() {
  const { hasScope } = useAuth();
  const canAdmin = hasScope(SCOPE_ADMIN);
  const { refresh: refreshLiveSpec } = useLiveSpec();
  const [status, setStatus] = useState<Status | null>(null);
  const [features, setFeatures] = useState<FeatureList | null>(null);
  const [liveState, setLiveState] = useState<StateView | null>(null);
  const [stateError, setStateError] = useState("");
  const [revision, setRevision] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [featureError, setFeatureError] = useState("");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);

  const [tlsIntercept, setTlsIntercept] = useState(true);
  const [tlsPorts, setTlsPorts] = useState("443");
  const [httpAuthEnabled, setHttpAuthEnabled] = useState(false);
  const [httpAuthRealm, setHttpAuthRealm] = useState("labmitm-proxy");
  const [httpAuthUsers, setHttpAuthUsers] = useState("[]");
  const [rulesItems, setRulesItems] = useState("[]");
  const [admission, setAdmission] = useState<AdmissionSpec | null>(null);
  const [compatPrefix, setCompatPrefix] = useState("/compat");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const st = await getStatus();
        if (!cancelled) {
          setStatus(st);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load status.");
        }
      }
    })();
    void (async () => {
      try {
        const list = await getFeatures();
        if (!cancelled) {
          setFeatures(list);
          setRevision(list.runtimeRevision);
        }
      } catch (err) {
        if (!cancelled) {
          setFeatureError(err instanceof APIError ? err.message : "Could not load features.");
        }
      }
    })();
    void (async () => {
      try {
        const sv = await getState();
        if (!cancelled) {
          applyStateToForms(sv);
          setStateError("");
        }
      } catch (err) {
        if (!cancelled) {
          setStateError(err instanceof APIError ? err.message : "Could not load state.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  function applyStateToForms(sv: StateView): void {
    setLiveState(sv);
    if (sv.runtimeRevision !== "") {
      setRevision(sv.runtimeRevision);
    }
    const spec = sv.canonical?.spec;
    const tls = spec?.tls;
    if (tls && Array.isArray(tls.ports)) {
      setTlsIntercept(tls.intercept);
      setTlsPorts(tls.ports.join(","));
    }
    const auth = spec?.proxy?.httpAuth;
    if (auth) {
      setHttpAuthEnabled(auth.enabled);
      setHttpAuthRealm(auth.realm);
      setHttpAuthUsers(JSON.stringify(auth.users ?? [], null, 2));
    }
    const rules = spec?.rules;
    if (rules) {
      setRulesItems(JSON.stringify(rules.items ?? [], null, 2));
    }
    const adm = spec?.proxy?.admission;
    if (adm) {
      setAdmission({ ...adm });
    }
    const prefix = spec?.compat?.flowREST?.pathPrefix;
    if (prefix !== undefined) {
      setCompatPrefix(prefix);
    }
  }

  async function refreshFeatures(): Promise<FeatureList> {
    const list = await getFeatures();
    setFeatures(list);
    if (list.runtimeRevision !== "") {
      setRevision(list.runtimeRevision);
    }
    return list;
  }

  async function refreshAll(): Promise<void> {
    try {
      const st = await getStatus();
      setStatus(st);
    } catch {
      // Keep the apply problem+json detail.
    }
    try {
      await refreshFeatures();
    } catch {
      // Keep the apply problem+json detail.
    }
    try {
      const sv = await getState();
      applyStateToForms(sv);
      setStateError("");
    } catch {
      // Keep the apply problem+json detail.
    }
    try {
      await refreshLiveSpec();
    } catch {
      // Chip refresh is best-effort.
    }
  }

  async function liveEnabled(id: string, fallback: boolean): Promise<boolean> {
    try {
      const list = await refreshFeatures();
      const row = list.items.find((item) => item.id === id);
      if (row) {
        return row.enabled;
      }
    } catch {
      // Fall through to state.
    }
    try {
      const sv = await getState();
      if (id === FEATURE_RULES_ENABLED) {
        return sv.canonical?.spec?.rules?.enabled ?? fallback;
      }
      if (id === FEATURE_COMPAT) {
        return sv.canonical?.spec?.compat?.flowREST?.enabled ?? fallback;
      }
    } catch {
      // Use the caller fallback (fresh subtree or last known).
    }
    return fallback;
  }

  async function applyOp(
    operations: ChangeOperation[] | (() => Promise<ChangeOperation[]>),
  ): Promise<boolean> {
    if (busyRef.current) {
      return false;
    }
    busyRef.current = true;
    setBusy(true);
    setFeatureError("");
    const idempotencyKey = crypto.randomUUID();
    try {
      const ops = typeof operations === "function" ? await operations() : operations;
      const fresh = await getState();
      const expectedRevision = fresh.runtimeRevision || revision;
      const result = await applyChanges({
        expectedRevision,
        idempotencyKey,
        reason: reason.trim(),
        operations: ops,
      });
      if (result.runtimeRevision) {
        setRevision(result.runtimeRevision);
      }
      await refreshAll();
      return true;
    } catch (err) {
      const detail =
        err instanceof APIError ? err.problem.detail || err.message : "Could not apply change.";
      setFeatureError(detail);
      if (err instanceof APIError && err.problem.status === 409) {
        try {
          await refreshAll();
        } catch {
          // Keep the apply problem+json detail.
        }
      }
      return false;
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  async function onToggle(feature: Feature) {
    if (!featureToggleable(feature, canAdmin) || busyRef.current) {
      return;
    }
    if (feature.id === FEATURE_UI_ENABLED && feature.enabled) {
      if (!window.confirm(UI_OFF_CONFIRM)) {
        return;
      }
    }
    await applyOp([
      {
        op: "setFeature",
        feature: { id: feature.id, enabled: !feature.enabled },
      },
    ]);
  }

  async function onApplyTLS(ev: FormEvent) {
    ev.preventDefault();
    const tls = liveState?.canonical?.spec?.tls;
    if (!tls || !canAdmin) {
      return;
    }
    const parsed = parsePorts(tlsPorts);
    if (typeof parsed === "string") {
      setFeatureError(parsed);
      return;
    }
    const body: TLSSpec = {
      intercept: tlsIntercept,
      hosts: tls.hosts ?? [],
      ports: parsed,
      ca: { ...(tls.ca ?? { mode: "generate", certFile: "", keyFile: "" }) },
      upstream: {
        insecureSkipVerify: tls.upstream?.insecureSkipVerify ?? false,
        extraCAFiles: [...(tls.upstream?.extraCAFiles ?? [])],
      },
    };
    await applyOp([{ op: "replaceTLS", tls: body }]);
  }

  async function onApplyHTTPAuth(ev: FormEvent) {
    ev.preventDefault();
    const current = liveState?.canonical?.spec?.proxy?.httpAuth;
    if (!current || !canAdmin) {
      return;
    }
    let users: HTTPAuthUser[];
    try {
      const parsed = JSON.parse(httpAuthUsers) as unknown;
      if (!Array.isArray(parsed)) {
        setFeatureError("httpAuth users must be a JSON array.");
        return;
      }
      users = [];
      for (const row of parsed) {
        if (!row || typeof row !== "object") {
          setFeatureError("httpAuth users must be objects with id, usernameFile, passwordFile.");
          return;
        }
        const rec = row as Record<string, unknown>;
        if (
          typeof rec.id !== "string" ||
          typeof rec.usernameFile !== "string" ||
          typeof rec.passwordFile !== "string"
        ) {
          setFeatureError("httpAuth users must be objects with id, usernameFile, passwordFile.");
          return;
        }
        users.push({
          id: rec.id,
          usernameFile: rec.usernameFile,
          passwordFile: rec.passwordFile,
        });
      }
    } catch {
      setFeatureError("httpAuth users JSON is invalid.");
      return;
    }
    if (httpAuthEnabled && users.length < 1) {
      setFeatureError("httpAuth.users is required when enabled.");
      return;
    }
    const body: HTTPAuthSpec = {
      enabled: httpAuthEnabled,
      realm: httpAuthRealm,
      users,
    };
    await applyOp([{ op: "replaceHTTPAuth", httpAuth: body }]);
  }

  async function onApplyRules(ev: FormEvent) {
    ev.preventDefault();
    const current = liveState?.canonical?.spec?.rules;
    if (!current || !canAdmin) {
      return;
    }
    let items: unknown[];
    try {
      const parsed = JSON.parse(rulesItems) as unknown;
      if (!Array.isArray(parsed)) {
        setFeatureError("rules items must be a JSON array.");
        return;
      }
      items = parsed;
    } catch {
      setFeatureError("rules items JSON is invalid.");
      return;
    }
    await applyOp(async () => {
      const enabled = await liveEnabled(FEATURE_RULES_ENABLED, current.enabled);
      return [{ op: "replaceRules", rules: { enabled, items } }];
    });
  }

  async function onApplyAdmission(ev: FormEvent) {
    ev.preventDefault();
    if (!admission || !liveState?.canonical?.spec?.proxy?.admission || !canAdmin) {
      return;
    }
    await applyOp([{ op: "replaceAdmission", admission: { ...admission } }]);
  }

  async function onApplyCompat(ev: FormEvent) {
    ev.preventDefault();
    const current = liveState?.canonical?.spec?.compat?.flowREST;
    if (!current || !canAdmin) {
      return;
    }
    await applyOp(async () => {
      const enabled = await liveEnabled(FEATURE_COMPAT, current.enabled);
      return [
        {
          op: "replaceCompat",
          compat: { flowREST: { enabled, pathPrefix: compatPrefix } },
        },
      ];
    });
  }

  if (error !== "") {
    return (
      <main className="page">
        <p className="kicker">Status</p>
        <h1>Status</h1>
        <p className="banner-error" role="alert">
          {error}
        </p>
      </main>
    );
  }
  if (status === null) {
    return (
      <main className="page">
        <p className="kicker">Status</p>
        <h1>Status</h1>
        <p className="muted" role="status">
          Loading status…
        </p>
      </main>
    );
  }

  const spec = liveState?.canonical?.spec;
  const tlsReady = spec?.tls != null && Array.isArray(spec.tls.ports);
  const authReady = spec?.proxy?.httpAuth != null;
  const rulesReady = spec?.rules != null;
  const admissionReady = spec?.proxy?.admission != null && admission != null;
  const compatReady = spec?.compat?.flowREST != null;
  const origDestAddr = spec?.listeners?.originalDestination?.address ?? "";
  const metricsListen = spec?.observability?.metrics?.listen ?? "";

  return (
    <main className="page">
      <p className="kicker">Status</p>
      <h1>Status</h1>
      <p className="banner-warn">
        Lab-only intercepting proxy. Install the lab CA only on systems under test and uninstall it
        after use. LabMITM is not a public MITM product.
      </p>
      <p>
        Ready: <strong>{status.ready ? "yes" : "no"}</strong>
        {" · "}
        Intercept: <strong>{status.intercept ? "on" : "off"}</strong>
      </p>
      <section className="panel">
        <h2>Lab CA</h2>
        <dl>
          <div>
            <dt>Mode</dt>
            <dd>{status.ca.mode || "—"}</dd>
          </div>
          <div>
            <dt>SPKI SHA-256</dt>
            <dd>
              <code>{status.ca.spkiSha256 || "—"}</code>
            </dd>
          </div>
          <div>
            <dt>Subject</dt>
            <dd>{status.ca.subject || "—"}</dd>
          </div>
          <div>
            <dt>Not after</dt>
            <dd>{status.ca.notAfter || "—"}</dd>
          </div>
        </dl>
        <p>
          <a href={CA_DOWNLOAD_URL} download="labmitm-ca.pem">
            Download lab CA certificate
          </a>{" "}
          <span className="muted">(PEM cert only; the private key is never exported)</span>
        </p>
      </section>
      <section className="panel">
        <h2>Store</h2>
        <dl>
          <div>
            <dt>Flows</dt>
            <dd>{status.store.flowCount}</dd>
          </div>
          <div>
            <dt>Bytes</dt>
            <dd>{formatBytes(status.store.storeBytes)}</dd>
          </div>
          <div>
            <dt>Generation</dt>
            <dd>{status.store.storeGeneration}</dd>
          </div>
          <div>
            <dt>Epoch</dt>
            <dd>{status.store.epoch}</dd>
          </div>
        </dl>
      </section>
      <section className="panel">
        <h2>Listeners</h2>
        <ul>
          {status.listeners.map((l) => (
            <li key={l.name}>
              {l.name}: <code>{l.address}</code>
            </li>
          ))}
        </ul>
        <p className="muted">Listener addresses are bootstrap + Reset only.</p>
        <p>
          originalDestination address:{" "}
          {origDestAddr !== "" ? (
            <code>{origDestAddr}</code>
          ) : (
            <span className="muted">unset until enabled (normalize default 127.0.0.1:8890)</span>
          )}
        </p>
        <p>
          metrics.listen:{" "}
          {metricsListen !== "" ? (
            <code>{metricsListen}</code>
          ) : (
            <span className="muted">unset</span>
          )}{" "}
          <span className="muted">Reset required</span>
        </p>
      </section>
      <section className="panel">
        <h2>Runtime flags</h2>
        <p>
          httpAuth: <span className="badge">{status.features.httpAuth ? "on" : "off"}</span>
          {" · "}
          live <code>replaceHTTPAuth</code>
        </p>
        <table className="data">
          <thead>
            <tr>
              <th>ID</th>
              <th>Enabled</th>
              <th>Apply</th>
            </tr>
          </thead>
          <tbody>
            {RESET_ONLY_FLAGS.map((row) => (
              <tr key={row.key}>
                <td>
                  <code>{row.label}</code>
                </td>
                <td>
                  <span className="badge">{status.features[row.key] ? "on" : "off"}</span>
                </td>
                <td>
                  <span className="muted">Reset required</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="panel">
        <h2>Features</h2>
        {featureError !== "" ? (
          <p className="banner-error" role="alert">
            {featureError}
          </p>
        ) : null}
        {features === null && featureError === "" ? (
          <p className="muted" role="status">
            Loading features…
          </p>
        ) : null}
        {features !== null ? (
          <>
            {canAdmin ? (
              <div className="field">
                <label htmlFor="feature-reason">Reason (optional)</label>
                <input
                  id="feature-reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </div>
            ) : null}
            <table className="data">
            <thead>
              <tr>
                <th>ID</th>
                <th>Enabled</th>
                <th>Apply</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {features.items.map((f) => (
                <tr key={f.id}>
                  <td>
                    <code>{f.id}</code>
                  </td>
                  <td>
                    <span className="badge">{f.enabled ? "on" : "off"}</span>
                    {featureToggleable(f, canAdmin) ? (
                      <input
                        type="checkbox"
                        role="switch"
                        checked={f.enabled}
                        disabled={busy}
                        aria-label={`Toggle ${f.id}`}
                        onChange={() => void onToggle(f)}
                      />
                    ) : null}
                  </td>
                  <td>
                    <span>{f.applyMode}</span>
                    {f.applyMode === "reset" ? (
                      <>
                        {" "}
                        <Link to="/reset">Reset required</Link>
                      </>
                    ) : null}
                  </td>
                  <td>{f.description}</td>
                </tr>
              ))}
            </tbody>
            </table>
          </>
        ) : null}
      </section>
      <section className="panel">
        <h2>TLS intercept</h2>
        {stateError !== "" ? (
          <p className="banner-error" role="alert">
            {stateError}
          </p>
        ) : null}
        {!tlsReady ? (
          <p className="muted">Load GET /v1/state to edit tls.ports.</p>
        ) : (
          <form className="stack" onSubmit={(e) => void onApplyTLS(e)}>
            <p className="muted">
              generate-mode CA rotates when the TLS spec changes. Full subtree replace.
            </p>
            <label>
              <input
                type="checkbox"
                checked={tlsIntercept}
                disabled={!canAdmin || busy}
                onChange={(e) => setTlsIntercept(e.target.checked)}
              />{" "}
              intercept
            </label>
            <div className="field">
              <label htmlFor="tls-ports">Ports</label>
              <input
                id="tls-ports"
                value={tlsPorts}
                disabled={!canAdmin || busy}
                onChange={(e) => setTlsPorts(e.target.value)}
              />
            </div>
            {canAdmin ? (
              <button type="submit" disabled={busy}>
                Apply TLS
              </button>
            ) : null}
          </form>
        )}
      </section>
      <section className="panel">
        <h2>
          HTTP proxy 407{" "}
          <span className="badge">{status.features.httpAuth ? "on" : "off"}</span>
        </h2>
        {!authReady ? (
          <p className="muted">Load GET /v1/state to edit httpAuth.</p>
        ) : (
          <form className="stack" onSubmit={(e) => void onApplyHTTPAuth(e)}>
            <label>
              <input
                type="checkbox"
                checked={httpAuthEnabled}
                disabled={!canAdmin || busy}
                onChange={(e) => setHttpAuthEnabled(e.target.checked)}
              />{" "}
              httpAuth enabled
            </label>
            <div className="field">
              <label htmlFor="http-auth-realm">Realm</label>
              <input
                id="http-auth-realm"
                value={httpAuthRealm}
                disabled={!canAdmin || busy}
                onChange={(e) => setHttpAuthRealm(e.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor="http-auth-users">Users (file refs)</label>
              <textarea
                id="http-auth-users"
                value={httpAuthUsers}
                disabled={!canAdmin || busy}
                rows={6}
                spellCheck={false}
                onChange={(e) => setHttpAuthUsers(e.target.value)}
              />
            </div>
            {canAdmin ? (
              <button type="submit" disabled={busy}>
                Apply HTTP auth
              </button>
            ) : null}
          </form>
        )}
      </section>
      <section className="panel">
        <h2>Rules</h2>
        {!rulesReady ? (
          <p className="muted">Load GET /v1/state to edit rules items.</p>
        ) : (
          <form className="stack" onSubmit={(e) => void onApplyRules(e)}>
            <div className="field">
              <label htmlFor="rules-items">Items JSON</label>
              <textarea
                id="rules-items"
                value={rulesItems}
                disabled={!canAdmin || busy}
                rows={8}
                spellCheck={false}
                onChange={(e) => setRulesItems(e.target.value)}
              />
            </div>
            {canAdmin ? (
              <button type="submit" disabled={busy}>
                Apply rules
              </button>
            ) : null}
          </form>
        )}
      </section>
      <section className="panel">
        <h2>Admission</h2>
        {!admissionReady ? (
          <p className="muted">Load GET /v1/state to edit admission.</p>
        ) : (
          <form className="stack" onSubmit={(e) => void onApplyAdmission(e)}>
            <p className="muted">http.Server.IdleTimeout stays Start-time.</p>
            {(
              [
                ["maxSessions", "maxSessions"],
                ["maxSessionsPerIP", "maxSessionsPerIP"],
                ["maxInFlight", "maxInFlight"],
                ["maxConcurrentStreams", "maxConcurrentStreams"],
              ] as const
            ).map(([key, label]) => (
              <div className="field" key={key}>
                <label htmlFor={`adm-${key}`}>{label}</label>
                <input
                  id={`adm-${key}`}
                  value={String(admission[key])}
                  disabled={!canAdmin || busy}
                  onChange={(e) =>
                    setAdmission({
                      ...admission,
                      [key]: Number.parseInt(e.target.value, 10) || 0,
                    })
                  }
                />
              </div>
            ))}
            <div className="field">
              <label htmlFor="adm-maxInFlightBytes">maxInFlightBytes</label>
              <input
                id="adm-maxInFlightBytes"
                value={admission.maxInFlightBytes}
                disabled={!canAdmin || busy}
                onChange={(e) => setAdmission({ ...admission, maxInFlightBytes: e.target.value })}
              />
            </div>
            {(
              [
                ["sessionTimeout", "sessionTimeout"],
                ["idleTimeout", "idleTimeout"],
                ["headerTimeout", "headerTimeout"],
                ["dialTimeout", "dialTimeout"],
                ["upstreamTimeout", "upstreamTimeout"],
              ] as const
            ).map(([key, label]) => (
              <div className="field" key={key}>
                <label htmlFor={`adm-${key}`}>{label}</label>
                <input
                  id={`adm-${key}`}
                  value={admission[key]}
                  disabled={!canAdmin || busy}
                  onChange={(e) => setAdmission({ ...admission, [key]: e.target.value })}
                />
              </div>
            ))}
            {canAdmin ? (
              <button type="submit" disabled={busy}>
                Apply admission
              </button>
            ) : null}
          </form>
        )}
      </section>
      <section className="panel">
        <h2>Compat prefix</h2>
        {!compatReady ? (
          <p className="muted">Load GET /v1/state to edit pathPrefix.</p>
        ) : (
          <form className="stack" onSubmit={(e) => void onApplyCompat(e)}>
            <div className="field">
              <label htmlFor="compat-prefix">pathPrefix</label>
              <input
                id="compat-prefix"
                value={compatPrefix}
                disabled={!canAdmin || busy}
                onChange={(e) => setCompatPrefix(e.target.value)}
              />
            </div>
            {canAdmin ? (
              <button type="submit" disabled={busy}>
                Apply compat
              </button>
            ) : null}
          </form>
        )}
      </section>
      <section className="panel">
        <h2>Revisions</h2>
        <pre className="raw">{JSON.stringify(status.revisions, null, 2)}</pre>
      </section>
    </main>
  );
}
