import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useMatch, useNavigate } from "react-router-dom";
import { clearFlows, errorMessage, listAllFlows } from "../api/client";
import type { Flow, FlowListQuery } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE, formatBytes } from "../auth/scopes";
import { useFlowsLive } from "../hooks/useFlowsLive";
import { useConfirm } from "../ui/ConfirmDialog";
import {
  FLOWS_FOOTER,
  flowAuthority,
  flowPath,
  listStatusText,
  listTimingLabel,
  matchesFlowSearch,
  methodLabel,
  methodTone,
  statusBucket,
  statusTone,
  type StatusBucket,
} from "../ui/flowKind";
import { FlowInspector, SelectFlowEmpty } from "./FlowInspector";

import { FlowFilters } from "./FlowFilters";

type Bucket = "all" | StatusBucket;
const BUCKETS: { id: Bucket; label: string; tone: string }[] = [
  { id: "all", label: "All", tone: "" },
  { id: "paused", label: "Paused", tone: "chip-accent" },
  { id: "2xx", label: "2xx", tone: "chip-ok" },
  { id: "4xx", label: "4xx", tone: "chip-warn" },
  { id: "5xx", label: "5xx · error", tone: "chip-danger" },
];

const TONE_CLASS: Record<ReturnType<typeof statusTone>, string> = {
  ok: "status-ok",
  tunnel: "status-tunnel",
  warn: "status-warn",
  danger: "status-danger",
  muted: "status-muted",
  paused: "chip chip-accent chip-fill",
};

export function FlowsWorkspace() {
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const navigate = useNavigate();
  const selected = useMatch("/flows/:id")?.params.id ?? "";
  const selectedRef = useRef(selected);
  selectedRef.current = selected;
  const navigateRef = useRef(navigate);
  navigateRef.current = navigate;
  const queryRef = useRef<FlowListQuery>({});
  const requestVersion = useRef(0);
  const [clearGeneration, setClearGeneration] = useState("");
  // Read after the confirm resolves; the dialog edits it while onClear awaits.
  const clearGenerationRef = useRef(clearGeneration);
  clearGenerationRef.current = clearGeneration;
  const [items, setItems] = useState<Flow[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [filtered, setFiltered] = useState(false);
  const [justCleared, setJustCleared] = useState(false);
  const [search, setSearch] = useState("");
  const [bucket, setBucket] = useState<Bucket>("all");
  const [error, setError] = useState("");
  const [generation, setGeneration] = useState<number | null>(null);
  const [triggerHost, setTriggerHost] = useState<HTMLSpanElement | null>(null);
  const [popoverHost, setPopoverHost] = useState<HTMLDivElement | null>(null);
  const [renderConfirm, confirm] = useConfirm();
  const clearGenerationId = useId();

  // useCallback(..., []) only — selected/navigate/search/generation in deps
  // reconnect EventSource (useFlowsLive [enabled, onChange]).
  const refresh = useCallback(() => {
    void (async () => {
      const version = ++requestVersion.current;
      try {
        const list = await listAllFlows(queryRef.current);
        if (version !== requestVersion.current) return;
        setItems(list.items);
        setLoaded(true);
        if (list.items.length > 0) setJustCleared(false);
        setGeneration(list.storeGeneration);
        setError("");
        const id = selectedRef.current;
        if (Object.keys(queryRef.current).length === 0 && id !== "" && !list.items.some((f) => f.id === id)) {
          navigateRef.current("/", { replace: true });
        }
      } catch (err) {
        if (version === requestVersion.current) setError(errorMessage(err, "Could not load flows.", true));
      }
    })();
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const mode = useFlowsLive(refresh, true);
  const searched = useMemo(() => items.filter((f) => matchesFlowSearch(f, search)), [items, search]);
  const counts = useMemo(() => {
    const c: Record<Bucket, number> = { all: searched.length, paused: 0, "2xx": 0, "4xx": 0, "5xx": 0 };
    for (const f of searched) {
      const b = statusBucket(f);
      if (b !== null) c[b]++;
    }
    return c;
  }, [searched]);
  const visible = useMemo(
    () => (bucket === "all" ? searched : searched.filter((f) => statusBucket(f) === bucket)),
    [searched, bucket],
  );

  async function onClear() {
    const ok = await confirm({
      title: "Clear every captured flow?",
      body: (
        <>
          <p>
            {filtered
              ? `Deletes every flow in the store, not only the ${items.length} that ${items.length === 1 ? "matches" : "match"} the current server filters.`
              : `Deletes every flow in the store: ${items.length} as of the last refresh, plus anything captured since.`}
          </p>
          {generation !== null ? <p>Current store generation {generation}.</p> : null}
        </>
      ),
      confirmLabel: "Clear flows",
      danger: true,
    });
    if (!ok) {
      return;
    }
    try {
      const expected = clearGenerationRef.current;
      await clearFlows(expected === "" ? undefined : Number(expected));
      setJustCleared(true);
      navigate("/", { replace: true });
      refresh();
    } catch (err) {
      setError(errorMessage(err, "Clear failed."));
    }
  }

  const narrowed = search.trim() !== "" || bucket !== "all";
  let empty: ReactNode = null;
  if (visible.length === 0) {
    if (justCleared && !narrowed && !filtered) {
      empty = (
        <div className="empty-state">
          <p className="empty-title">Flows cleared</p>
          <p>New captures appear here as they arrive.</p>
        </div>
      );
    } else if (items.length > 0 || filtered || narrowed) {
      empty = (
        <div className="empty-state">
          <p className="empty-title">No flows match</p>
          <p>Nothing loaded matches the current search, status chip or server filters.</p>
          {narrowed ? (
            <button
              type="button"
              className="btn-sm"
              onClick={() => {
                setSearch("");
                setBucket("all");
              }}
            >
              Clear search and status
            </button>
          ) : null}
        </div>
      );
    } else {
      empty = (
        <div className="empty-state">
          <p className="empty-title">{loaded ? "No flows captured yet" : "No flows."}</p>
          {loaded ? <p>Send traffic through the proxy listener; captures appear here live.</p> : null}
        </div>
      );
    }
  }

  return (
    <main className="workspace">
      <section className="workspace-list" aria-label="Captured flows">
        <div className="list-head">
          <div className="list-head-row">
            <p className="kicker">
              Captured <span className="mono">{narrowed ? `${visible.length} of ${items.length}` : items.length}</span>
              {filtered ? " filtered" : ""}
            </p>
            <span className="actions" style={{ marginTop: 0 }}>
              <span ref={setTriggerHost} style={{ display: "contents" }} />
              {canWrite ? (
                <button type="button" className="btn-sm btn-danger" onClick={() => void onClear()}>
                  Clear flows<span aria-hidden="true">…</span>
                </button>
              ) : null}
            </span>
          </div>
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
          </form>
          <div className="chip-row" role="group" aria-label="Status filter">
            {BUCKETS.map((b) => (
              <button
                key={b.id}
                type="button"
                className={`chip ${b.tone}`}
                aria-pressed={bucket === b.id}
                onClick={() => setBucket(b.id)}
              >
                {b.label}
                <span className="n">{counts[b.id]}</span>
              </button>
            ))}
          </div>
          <FlowFilters
            triggerHost={triggerHost}
            popoverHost={popoverHost}
            onFilter={(query) => {
              queryRef.current = query;
              setFiltered(Object.keys(query).length > 0);
              setItems([]);
              setError("");
              refresh();
            }}
          />
          {error !== "" ? (
            <p className="banner-error" role="alert">
              {error}
            </p>
          ) : null}
        </div>
        <div className="list-scroll">
          {empty ?? (
            <ul className="flow-list">
              {visible.map((f) => {
                const selectedRow = f.id === selected;
                const tone = statusTone(f);
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
                        <span className={TONE_CLASS[tone]}>{listStatusText(f)}</span>
                      </span>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <p className="list-live muted">
          Live update: {mode === "sse" ? "event stream" : mode === "poll" ? "3s poll fallback" : "connecting…"}.
          {generation !== null ? ` Store generation ${generation}.` : ""}
        </p>
      </section>
      <section className="workspace-inspector" aria-label="Flow inspector">
        {selected !== "" ? (
          <FlowInspector storeGeneration={generation ?? undefined} id={selected} embedded onDeleted={refresh} />
        ) : (
          <SelectFlowEmpty />
        )}
      </section>
      <div ref={setPopoverHost} className="popover-slot" />
      <p className="workspace-footer muted">{FLOWS_FOOTER}</p>
      {renderConfirm(
        canWrite ? (
          <>
            <label htmlFor={clearGenerationId}>Clear expected store generation (optional)</label>
            <input
              id={clearGenerationId}
              type="number"
              min="0"
              step="1"
              placeholder={generation === null ? "Any generation" : `Current ${generation}`}
              value={clearGeneration}
              onChange={(e) => setClearGeneration(e.target.value)}
            />
          </>
        ) : null,
      )}
    </main>
  );
}
