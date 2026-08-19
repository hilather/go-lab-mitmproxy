import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, clearFlows, listAllFlows } from "../api/client";
import type { Flow, FlowListQuery } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE } from "../auth/scopes";
import { useFlowsLive } from "../hooks/useFlowsLive";

export function FlowsPage() {
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const [items, setItems] = useState<Flow[]>([]);
  const [filter, setFilter] = useState<FlowListQuery>({});
  const [error, setError] = useState("");
  const [generation, setGeneration] = useState<number | null>(null);

  const refresh = useCallback(() => {
    void (async () => {
      try {
        const list = await listAllFlows(filter);
        setItems(list.items);
        setGeneration(list.storeGeneration);
        setError("");
      } catch (err) {
        setError(err instanceof APIError ? err.message : "Could not load flows.");
      }
    })();
  }, [filter]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const mode = useFlowsLive(refresh, true);

  async function onClear() {
    if (!window.confirm("Delete every captured flow?")) {
      return;
    }
    try {
      await clearFlows();
      refresh();
    } catch (err) {
      setError(err instanceof APIError ? err.message : "Clear failed.");
    }
  }

  return (
    <main className="page">
      <h1>Flows</h1>
      <p className="muted">
        Live update: {mode === "sse" ? "event stream" : mode === "poll" ? "3s poll fallback" : "connecting…"}.
        {generation !== null ? ` Store generation ${generation}.` : ""}
      </p>
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <form
        className="row"
        onSubmit={(ev) => {
          ev.preventDefault();
          const fd = new FormData(ev.currentTarget);
          const next: FlowListQuery = {};
          const host = String(fd.get("host") ?? "").trim();
          const method = String(fd.get("method") ?? "").trim();
          if (host !== "") {
            next.host = host;
          }
          if (method !== "") {
            next.method = method;
          }
          setFilter(next);
        }}
      >
        <div className="field">
          <label htmlFor="flow-host">Host</label>
          <input id="flow-host" name="host" defaultValue={filter.host ?? ""} />
        </div>
        <div className="field">
          <label htmlFor="flow-method">Method</label>
          <input id="flow-method" name="method" defaultValue={filter.method ?? ""} />
        </div>
        <button type="submit">Filter</button>
        {canWrite ? (
          <button type="button" onClick={() => void onClear()}>
            Clear flows
          </button>
        ) : null}
      </form>
      {items.length === 0 ? (
        <p>No flows.</p>
      ) : (
        <>
          <p className="muted">Showing {items.length} flows.</p>
          <ul className="flow-list">
            {items.map((f) => (
              <li key={f.id}>
                <Link to={`/flows/${encodeURIComponent(f.id)}`}>
                  <span>
                    <span className="badge">{f.method || "?"}</span>
                    <span className="badge">{f.protocol || "?"}</span>
                  </span>
                  <span>
                    <span className="subject">
                      {f.status > 0 ? f.status : f.state} {f.host || f.url}
                    </span>
                    <span className="muted"> {f.url}</span>
                    {f.http2 != null ? <span className="badge">stream {f.http2.streamId}</span> : null}
                    {f.socks?.dest ? <span className="muted"> SOCKS dest {f.socks.dest}</span> : null}
                    {f.originalDest ? <span className="muted"> original dest {f.originalDest}</span> : null}
                    {f.intercepted ? <span className="badge">intercepted</span> : null}
                  </span>
                  <time dateTime={f.startedAt}>{f.startedAt ?? ""}</time>
                </Link>
              </li>
            ))}
          </ul>
        </>
      )}
    </main>
  );
}
