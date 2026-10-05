import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useAuth } from "../auth/AuthProvider";
import { APIError, errorMessage } from "../api/client";
import {
  diagnosticReads,
  getDiagnostic,
  type DiagnosticRead,
} from "../api/diagnostics";
import { localTime } from "../ui/time";

type ReadState = {
  result: unknown;
  error: string;
  errorValue: unknown;
  loading: boolean;
  checkedAt: string;
};

function useDiagnostic(read: DiagnosticRead, token: number) {
  const generation = useRef(0);
  const [s, setS] = useState<ReadState>({
    result: undefined,
    error: "",
    errorValue: null,
    loading: false,
    checkedAt: "",
  });
  async function refresh() {
    const mine = ++generation.current;
    setS((prev) => ({ ...prev, loading: true, error: "", errorValue: null, result: undefined }));
    try {
      const value = await getDiagnostic(read);
      if (generation.current === mine)
        setS({ result: value, error: "", errorValue: null, loading: false, checkedAt: new Date().toISOString() });
    } catch (err) {
      if (generation.current === mine)
        setS({
          result: undefined,
          error: errorMessage(err, "Could not load diagnostics.", true),
          errorValue: err,
          loading: false,
          checkedAt: new Date().toISOString(),
        });
    }
  }
  useEffect(() => {
    void refresh();
    return () => {
      generation.current++;
    };
  }, [token]);
  return { ...s, refresh };
}

function rawText(result: unknown): string {
  return typeof result === "string" ? result : JSON.stringify(result, null, 2);
}

function obj(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function str(value: unknown): string {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean" ? String(value) : "";
}

function metricsDisabled(err: unknown): boolean {
  return err instanceof APIError && err.problem.status === 404 && err.problem.code === "not_found";
}

/** Shared frame: region label, endpoint, value, checked time, Raw details, Refresh button, alert. */
function DiagnosticFrame({
  read,
  d,
  className,
  children,
  hideError,
}: {
  read: DiagnosticRead;
  d: ReturnType<typeof useDiagnostic>;
  className: string;
  children?: ReactNode;
  hideError?: boolean;
}) {
  return (
    <section className={`panel card ${className}`} aria-label={read.title}>
      <div className="list-head-row">
        <h2 className="kicker">{read.title}</h2>
        <code className="hint">{read.path}</code>
      </div>
      {children}
      {d.loading && <p role="status" className="hint">Loading {read.title}…</p>}
      {d.error && !hideError && (
        <p role="alert" className="note note-danger">
          {d.error}
        </p>
      )}
      {d.result !== undefined && (
        <details>
          <summary>Raw {read.title}</summary>
          <pre className="raw diagnostic-output">{rawText(d.result)}</pre>
        </details>
      )}
      <div className="tile-actions">
        <button type="button" className="btn-sm" disabled={d.loading} onClick={() => void d.refresh()}>
          Refresh {read.title}
        </button>
        {d.checkedAt ? (
          <span className="hint">
            checked <time dateTime={d.checkedAt}>{localTime(d.checkedAt)}</time>
          </span>
        ) : null}
      </div>
    </section>
  );
}

function HealthTile({ read, token }: { read: DiagnosticRead; token: number }) {
  const d = useDiagnostic(read, token);
  const body = obj(d.result);
  const httpStatus = body.httpStatus;
  const ok = d.result !== undefined && httpStatus === undefined;
  const label = d.result === undefined ? (d.error ? "error" : "…") : ok ? str(body.status) || "ok" : str(body.status) || "not ready";
  return (
    <DiagnosticFrame read={read} d={d} className="tile">
      <p className={`tile-value ${ok ? "status-ok" : d.result !== undefined || d.error ? "status-danger" : ""}`}>
        {label}
        {httpStatus !== undefined ? <span className="hint"> · HTTP {str(httpStatus)}</span> : null}
      </p>
    </DiagnosticFrame>
  );
}

/** Version and Protocols tiles share one /v1/version read (no extra request). */
function VersionTiles({ read, token }: { read: DiagnosticRead; token: number }) {
  const d = useDiagnostic(read, token);
  const v = obj(d.result);
  const protocols = obj(v.protocols);
  const protocolRows = (["rest", "mcp", "configAPI"] as const).filter((k) => str(protocols[k]) !== "");
  return (
    <>
      <DiagnosticFrame read={read} d={d} className="tile">
        <p className="tile-value mono">{str(v.version) || (d.result === undefined ? "…" : "—")}</p>
        {d.result !== undefined ? (
          <p className="hint">
            {[str(v.commit) ? `commit ${str(v.commit).slice(0, 12)}` : "", str(v.buildTime) ? `built ${str(v.buildTime)}` : ""]
              .filter(Boolean)
              .join(" · ")}
          </p>
        ) : null}
      </DiagnosticFrame>
      <section className="panel card tile" aria-label="Protocols">
        <div className="list-head-row">
          <h2 className="kicker">Protocols</h2>
          <code className="hint">{read.path}</code>
        </div>
        {protocolRows.length > 0 ? (
          <dl className="kv">
            {protocolRows.map((k) => (
              <div key={k}>
                <dt>{k}</dt>
                <dd className="mono" title={str(protocols[k])}>{str(protocols[k])}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="hint">{d.loading ? "…" : "—"}</p>
        )}
        <p className="hint">From the Version read; refresh Version to update.</p>
      </section>
    </>
  );
}

function MetricsTile({ read, token }: { read: DiagnosticRead; token: number }) {
  const d = useDiagnostic(read, token);
  const disabled = metricsDisabled(d.errorValue);
  const series =
    typeof d.result === "string"
      ? d.result.split("\n").filter((line) => line.trim() !== "" && !line.startsWith("#")).length
      : 0;
  return (
    <DiagnosticFrame read={read} d={d} className="tile" hideError={disabled}>
      {disabled ? (
        <div className="note note-warn" role="status">
          <span className="mono">Metrics are disabled.</span>
          <span>
            Set <code>observability.metrics.publicPath: true</code> in bootstrap YAML and restart labmitm.
          </span>
        </div>
      ) : (
        <>
          <p className={`tile-value ${typeof d.result === "string" ? "status-ok" : ""}`}>
            {typeof d.result === "string" ? `enabled · ${series} series` : d.error ? "error" : "…"}
          </p>
          <p className="hint">
            Management metrics require <code>observability.metrics.publicPath: true</code> in bootstrap YAML and a
            restart of labmitm.
          </p>
        </>
      )}
    </DiagnosticFrame>
  );
}

type Capability = { name: string; mutating: boolean | undefined; idempotent: boolean | undefined; version: string; description: string };

function capabilityRows(result: unknown): Capability[] | null {
  const list = Array.isArray(result)
    ? result
    : Array.isArray(obj(result).capabilities)
      ? (obj(result).capabilities as unknown[])
      : Array.isArray(obj(result).items)
        ? (obj(result).items as unknown[])
        : null;
  if (list === null) return null;
  const rows: Capability[] = [];
  for (const raw of list) {
    const r = obj(raw);
    if (typeof r.name !== "string") return null;
    rows.push({
      name: r.name,
      mutating: typeof r.mutating === "boolean" ? r.mutating : undefined,
      idempotent: typeof r.idempotent === "boolean" ? r.idempotent : undefined,
      version: str(r.version),
      description: str(r.description),
    });
  }
  return rows;
}

function CapabilitiesCard({ read, token }: { read: DiagnosticRead; token: number }) {
  const d = useDiagnostic(read, token);
  const [kind, setKind] = useState<"all" | "mutating" | "read">("all");
  const [filter, setFilter] = useState("");
  const rows = useMemo(() => capabilityRows(d.result), [d.result]);
  const counts = {
    all: rows?.length ?? 0,
    mutating: rows?.filter((r) => r.mutating === true).length ?? 0,
    read: rows?.filter((r) => r.mutating === false).length ?? 0,
  };
  const visible = (rows ?? []).filter(
    (r) =>
      (kind === "all" || (kind === "mutating" ? r.mutating === true : r.mutating === false)) &&
      r.name.toLowerCase().includes(filter.trim().toLowerCase()),
  );
  return (
    <DiagnosticFrame read={read} d={d} className="caps">
      {rows ? (
        <>
          <div className="list-head-row">
            <div className="chip-row" role="group" aria-label="Capability kind">
              {(["all", "mutating", "read"] as const).map((k) => (
                <button
                  key={k}
                  type="button"
                  className="chip"
                  aria-pressed={kind === k}
                  onClick={() => setKind(k)}
                >
                  {k === "all" ? "All" : k === "mutating" ? "Mutating" : "Read"}
                  <span className="n">{counts[k]}</span>
                </button>
              ))}
            </div>
            <input
              aria-label="Filter by name"
              placeholder="Filter by name"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
          <table className="data" aria-label="Capabilities table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Idempotent</th>
                <th><abbr title="Capability version">Ver</abbr></th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((r) => (
                <tr key={r.name}>
                  <td className="nowrap">
                    <code>{r.name}</code>
                  </td>
                  <td>
                    {r.mutating === undefined ? (
                      "—"
                    ) : (
                      <span className={`chip ${r.mutating ? "chip-warn" : ""}`}>{r.mutating ? "mutating" : "read"}</span>
                    )}
                  </td>
                  <td>{r.idempotent === undefined ? "—" : r.idempotent ? "yes" : "no"}</td>
                  <td>{r.version || "—"}</td>
                  <td>{r.description || ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {visible.length === 0 ? <p className="hint">No capabilities match.</p> : null}
        </>
      ) : null}
    </DiagnosticFrame>
  );
}

function SchemaCard({ read, token }: { read: DiagnosticRead; token: number }) {
  const d = useDiagnostic(read, token);
  const s = obj(d.result);
  const props = obj(s.properties);
  const apiVersion = obj(props.apiVersion);
  const required = Array.isArray(s.required) ? (s.required as unknown[]).map(str).join(", ") : "";
  return (
    <DiagnosticFrame read={read} d={d} className="schema">
      {d.result !== undefined ? (
        <dl className="kv">
          <div>
            <dt>apiVersion</dt>
            <dd>{str(apiVersion.const) || (Array.isArray(apiVersion.enum) ? (apiVersion.enum as unknown[]).map(str).join(", ") : "—")}</dd>
          </div>
          <div>
            <dt>required</dt>
            <dd>{required || "—"}</dd>
          </div>
          <div>
            <dt>additionalProperties</dt>
            <dd>{s.additionalProperties === undefined ? "—" : str(s.additionalProperties) || "schema"}</dd>
          </div>
        </dl>
      ) : null}
      <a href={read.path} download="labmitm-config.schema.json">
        Download configuration schema
      </a>
    </DiagnosticFrame>
  );
}

function readById(id: DiagnosticRead["id"]): DiagnosticRead {
  return diagnosticReads.find((r) => r.id === id)!;
}

export function DiagnosticsPage() {
  const auth = useAuth();
  const [token, setToken] = useState(0);
  return (
    <main className="page page--wide">
      <div className="page-head">
        <div>
          <p className="kicker">Diagnostics</p>
          <h1>Diagnostics</h1>
          <p className="sub">Read-only health, version, capability, schema and metrics endpoints. Times in local time.</p>
        </div>
        {auth.state.status !== "loading" && auth.hasScope("mitm.read") ? (
          <button type="button" onClick={() => setToken((n) => n + 1)}>
            Refresh all
          </button>
        ) : null}
      </div>
      {auth.state.status === "loading" ? (
        <p role="status">Loading session…</p>
      ) : !auth.hasScope("mitm.read") ? (
        <p role="alert">Diagnostics require mitm.read.</p>
      ) : (
        <>
          <div className="tiles">
            <HealthTile read={readById("health.live")} token={token} />
            <HealthTile read={readById("health.ready")} token={token} />
            <VersionTiles read={readById("version.get")} token={token} />
            <MetricsTile read={readById("metrics.get")} token={token} />
          </div>
          <CapabilitiesCard read={readById("capabilities.get")} token={token} />
          <SchemaCard read={readById("schema.get")} token={token} />
        </>
      )}
    </main>
  );
}
