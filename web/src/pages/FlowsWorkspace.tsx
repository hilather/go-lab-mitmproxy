import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useMatch } from "react-router-dom";
import { APIError, clearFlows, listAllFlows } from "../api/client";
import type { Flow } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE, formatBytes } from "../auth/scopes";
import { useFlowsLive } from "../hooks/useFlowsLive";
import {
  FLOWS_FOOTER,
  flowAuthority,
  flowPath,
  isTunnelNotDecrypt,
  listStatusLabel,
  listTimingLabel,
  matchesFlowSearch,
  methodLabel,
  methodTone,
} from "../ui/flowKind";
import { FlowInspector } from "./FlowInspector";

export function FlowsWorkspace() {
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const selected = useMatch("/flows/:id")?.params.id ?? "";
  const [items, setItems] = useState<Flow[]>([]);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [generation, setGeneration] = useState<number | null>(null);

  const refresh = useCallback(() => {
    void (async () => {
      try {
        const list = await listAllFlows({});
        setItems(list.items);
        setGeneration(list.storeGeneration);
        setError("");
      } catch (err) {
        setError(err instanceof APIError ? err.message : "Could not load flows.");
      }
    })();
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const mode = useFlowsLive(refresh, true);
  const visible = useMemo(() => items.filter((f) => matchesFlowSearch(f, search)), [items, search]);

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
    <main className="workspace">
      <section className="workspace-list" aria-label="Captured flows">
        <p className="kicker">Captured</p>
        <form
          className="search-row"
          onSubmit={(ev) => {
            ev.preventDefault();
          }}
        >
          <label className="visually-hidden" htmlFor="flow-search">
            Host, method, or status
          </label>
          <input
            id="flow-search"
            name="q"
            placeholder="Host, method, or status"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {canWrite ? (
            <button type="button" onClick={() => void onClear()}>
              Clear flows
            </button>
          ) : null}
        </form>
        <p className="muted">
          Live update: {mode === "sse" ? "event stream" : mode === "poll" ? "3s poll fallback" : "connecting…"}.
          {generation !== null ? ` Store generation ${generation}.` : ""}
        </p>
        {error !== "" ? (
          <p className="banner-error" role="alert">
            {error}
          </p>
        ) : null}
        {visible.length === 0 ? (
          <p>No flows.</p>
        ) : (
          <ul className="flow-list">
            {visible.map((f) => {
              const selectedRow = f.id === selected;
              const tunnel = isTunnelNotDecrypt(f);
              return (
                <li key={f.id} className={selectedRow ? "flow-row-selected" : undefined}>
                  <Link to={`/flows/${encodeURIComponent(f.id)}`}>
                    <span className={`method method-${methodTone(f)}`}>{methodLabel(f)}</span>
                    <span className="flow-mid">
                      <span className="subject">{flowAuthority(f)}</span>
                      <span className="muted">{flowPath(f)}</span>
                    </span>
                    <span className="flow-meta">
                      <time>{listTimingLabel(f)}</time>
                      {f.requestBytes + f.responseBytes > 0 ? (
                        <span className="muted">{formatBytes(f.requestBytes + f.responseBytes)}</span>
                      ) : null}
                      <span className={tunnel ? "status-tunnel" : "status-ok"}>{listStatusLabel(f)}</span>
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      <section className="workspace-inspector" aria-label="Flow inspector">
        {selected !== "" ? (
          <FlowInspector id={selected} embedded onDeleted={refresh} />
        ) : (
          <p className="muted">Select a captured flow.</p>
        )}
      </section>
      <p className="workspace-footer muted">{FLOWS_FOOTER}</p>
    </main>
  );
}
