import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";
import { errorMessage } from "../api/client";
import { getAudit, queryAudit, type FullAuditEvent } from "../api/diagnostics";
import type { AuditEvent } from "../api/types";
import { DiffTable, RevisionChip } from "../ui/PlanReview";
import { localDateTime, localTime } from "../ui/time";

type ResultFilter = "all" | "ok" | "not-ok";

/** capabilityFamily groups capability names by their first dot segment. */
export function capabilityFamily(name: string | undefined): string {
  const n = name ?? "";
  const dot = n.indexOf(".");
  return dot < 0 ? n : n.slice(0, dot);
}

/** capabilityChips builds the mock's capability chips: a family with one distinct name shows that
 * name (e.g. "changes.apply"); several names sharing a prefix show "flows.*". */
export function capabilityChips(events: AuditEvent[]): { family: string; label: string; count: number }[] {
  const names = new Map<string, Set<string>>();
  const counts = new Map<string, number>();
  for (const ev of events) {
    const fam = capabilityFamily(ev.capability);
    if (fam === "") continue;
    if (!names.has(fam)) names.set(fam, new Set());
    names.get(fam)!.add(ev.capability ?? "");
    counts.set(fam, (counts.get(fam) ?? 0) + 1);
  }
  return Array.from(names.entries()).map(([family, set]) => ({
    family,
    label: set.size === 1 ? Array.from(set)[0]! : `${family}.*`,
    count: counts.get(family) ?? 0,
  }));
}

function resultTone(result: string | undefined): string {
  if (result === "ok") return "chip-ok";
  if (result === "denied") return "chip-warn";
  if (result === "error") return "chip-danger";
  return "";
}

export function AuditPage() {
  const auth = useAuth();
  const actorID = auth.state.status === "signed_in" ? auth.state.session.id : "";
  const permitted = auth.hasScope("mitm.audit.read");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [limit, setLimit] = useState("");
  const [eventId, setEventId] = useState("");
  const [detail, setDetail] = useState<FullAuditEvent>();
  const [error, setError] = useState("");
  const [detailError, setDetailError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [family, setFamily] = useState("all");
  const [result, setResult] = useState<ResultFilter>("all");
  const [tab, setTab] = useState<"change" | "raw">("change");
  const generation = useRef(0);
  const detailGeneration = useRef(0);
  async function refresh() {
    const mine = ++generation.current;
    setLoading(true);
    setError("");
    setEvents([]);
    try {
      const list = await queryAudit(limit === "" ? undefined : Number(limit));
      if (mine === generation.current) setEvents(list.events ?? []);
    } catch (err) {
      if (mine === generation.current) setError(errorMessage(err, "Could not load audit.", true));
    } finally {
      if (mine === generation.current) setLoading(false);
    }
  }
  async function lookup(id: string) {
    const mine = ++detailGeneration.current;
    setEventId(id);
    setTab("change");
    setDetail(undefined);
    setDetailError("");
    setDetailLoading(true);
    try {
      const ev = await getAudit(id);
      if (mine === detailGeneration.current) setDetail(ev);
    } catch (err) {
      if (mine === detailGeneration.current) setDetailError(errorMessage(err, "Could not load audit event.", true));
    } finally {
      if (mine === detailGeneration.current) setDetailLoading(false);
    }
  }
  useEffect(() => {
    setEvents([]);
    setError("");
    setLoading(false);
    setEventId("");
    setDetail(undefined);
    setDetailError("");
    setDetailLoading(false);
    if (permitted) void refresh();
    return () => {
      generation.current++;
      detailGeneration.current++;
    };
  }, [permitted, actorID]);

  const families = useMemo(() => capabilityChips(events), [events]);
  const familyShown = family === "all" || families.some((f) => f.family === family) ? family : "all";
  const byFamily = familyShown === "all" ? events : events.filter((ev) => capabilityFamily(ev.capability) === familyShown);
  const okCount = byFamily.filter((ev) => ev.result === "ok").length;
  const notOkCount = byFamily.filter((ev) => ev.result === "denied" || ev.result === "error").length;
  const visible = byFamily.filter((ev) =>
    result === "all" ? true : result === "ok" ? ev.result === "ok" : ev.result === "denied" || ev.result === "error",
  );

  return (
    <main className="page page--wide">
      <div className="page-head">
        <div>
          <p className="kicker">Audit</p>
          <h1>Audit</h1>
          <p className="sub">
            In-memory audit of control-plane and flow writes. Bodies and secrets are not recorded. Times in local time.
          </p>
        </div>
      </div>
      {auth.state.status === "loading" ? (
        <p role="status">Loading session…</p>
      ) : !permitted ? (
        <p role="alert">Audit requires mitm.audit.read.</p>
      ) : (
        <div className="split">
          <section className="panel card" aria-label="Audit events">
            <div className="card-h">
              <h2>
                Events <span className="chip">{events.length}</span>
              </h2>
              <span className="hint">Scoped to mitm.audit.read</span>
            </div>
            <div className="card-b">
              <form
                className="audit-lookup"
                onSubmit={(ev) => {
                  ev.preventDefault();
                  void lookup(eventId);
                }}
              >
                <label>
                  Event ID
                  <input
                    required
                    value={eventId}
                    onChange={(ev) => {
                      setEventId(ev.target.value);
                      detailGeneration.current++;
                      setDetail(undefined);
                      setDetailError("");
                      setDetailLoading(false);
                    }}
                  />
                </label>
                <button disabled={detailLoading || eventId === ""}>Find event</button>
              </form>
              <form
                className="audit-limit"
                onSubmit={(ev) => {
                  ev.preventDefault();
                  void refresh();
                }}
              >
                <label>
                  Limit
                  <input type="number" min="0" step="1" value={limit} onChange={(ev) => setLimit(ev.target.value)} />
                </label>
                <button disabled={loading}>Refresh audit</button>
                <p className="hint">Leave blank or use 0 for the latest 100 events. The server caps results at 100.</p>
              </form>
              <div className="chip-row" role="group" aria-label="Filter by capability">
                <button type="button" className="chip" aria-pressed={familyShown === "all"} onClick={() => setFamily("all")}>
                  All <span className="n">{events.length}</span>
                </button>
                {families.map((f) => (
                  <button
                    key={f.family}
                    type="button"
                    className="chip"
                    aria-pressed={familyShown === f.family}
                    onClick={() => setFamily(f.family)}
                  >
                    {f.label} <span className="n">{f.count}</span>
                  </button>
                ))}
              </div>
              <div className="chip-row" role="group" aria-label="Filter by result">
                <button type="button" className="chip" aria-pressed={result === "all"} onClick={() => setResult("all")}>
                  Any result
                </button>
                <button type="button" className="chip chip-ok" aria-pressed={result === "ok"} onClick={() => setResult("ok")}>
                  ok <span className="n">{okCount}</span>
                </button>
                <button
                  type="button"
                  className="chip chip-danger"
                  aria-pressed={result === "not-ok"}
                  onClick={() => setResult("not-ok")}
                >
                  not ok <span className="n">{notOkCount}</span>
                </button>
              </div>
            </div>
            {loading ? (
              <p role="status">Loading audit…</p>
            ) : error ? (
              <p role="alert">{error}</p>
            ) : events.length === 0 ? (
              <div className="panel empty-state">
                <p>No audit events.</p>
              </div>
            ) : visible.length === 0 ? (
              <p className="hint empty-state">No events match these chips.</p>
            ) : (
              <ul className="audit-rows" aria-label="Audit event list">
                {visible.map((ev) => (
                  <li key={ev.id}>
                    <button
                      type="button"
                      aria-current={detail?.id === ev.id ? "true" : undefined}
                      onClick={() => void lookup(ev.id)}
                    >
                      <time className="mono hint" dateTime={ev.time} title={ev.time}>
                        {localTime(ev.time)}
                      </time>
                      <span className="audit-row-main">
                        <span className="audit-cap nowrap">{ev.capability ?? "—"}</span>{" "}
                        <span className="hint wrap-anywhere">{ev.id}</span>
                        <span className="audit-row-sub hint">
                          {[ev.actorId, ev.transport, ev.flowId ? `flow ${ev.flowId}` : ev.reason]
                            .filter((v) => v)
                            .join(" · ")}
                        </span>
                      </span>
                      <span className={`chip ${resultTone(ev.result)}`}>{ev.result ?? "—"}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="panel card" aria-label="Audit event detail">
            <div className="card-h">
              <h2>
                {detail ? (
                  <>
                    {detail.capability ?? "Audit event"}{" "}
                    <span className={`chip ${resultTone(detail.result)}`}>{detail.result ?? "—"}</span>
                  </>
                ) : (
                  "Audit event detail"
                )}
              </h2>
            </div>
            <div className="card-b">
              {detailLoading && <p role="status">Loading audit event…</p>}
              {detailError && <p role="alert">{detailError}</p>}
              {!detail && !detailLoading && !detailError ? (
                <p className="hint empty-state">Select an event or look one up by ID to see its change and raw record.</p>
              ) : null}
              {detail ? (
                <>
                  <p className="hint wrap-anywhere">
                    {[
                      detail.id,
                      detail.time ? `${localDateTime(detail.time)} (${detail.time})` : "",
                      detail.actorId,
                      detail.actorClass,
                      detail.transport,
                    ]
                      .filter((v) => v)
                      .join(" · ")}
                  </p>
                  <div className="tabs" role="tablist" aria-label="Audit event views">
                    {(["change", "raw"] as const).map((t) => (
                      <button
                        key={t}
                        type="button"
                        role="tab"
                        id={`audit-tab-${t}`}
                        aria-controls={`audit-panel-${t}`}
                        aria-selected={tab === t}
                        onClick={() => setTab(t)}
                      >
                        {t === "change" ? "Change" : "Raw event"}
                      </button>
                    ))}
                  </div>
                  <div role="tabpanel" id="audit-panel-change" aria-labelledby="audit-tab-change" hidden={tab !== "change"}>
                    <dl className="kv">
                      {detail.flowId ? (
                        <div>
                          <dt>Flow</dt>
                          <dd>
                            <Link to={`/flows/${encodeURIComponent(detail.flowId)}`}>{detail.flowId}</Link>
                          </dd>
                        </div>
                      ) : null}
                      {detail.previous || detail.revision ? (
                        <div>
                          <dt>Revision</dt>
                          <dd>
                            <RevisionChip rev={detail.previous} /> → <RevisionChip rev={detail.revision} />
                          </dd>
                        </div>
                      ) : null}
                      {detail.storeGeneration !== undefined ? (
                        <div>
                          <dt>Store generation</dt>
                          <dd>{detail.storeGeneration}</dd>
                        </div>
                      ) : null}
                      {detail.reason ? (
                        <div>
                          <dt>Reason</dt>
                          <dd className="wrap-anywhere">{detail.reason}</dd>
                        </div>
                      ) : null}
                      {detail.errorCode ? (
                        <div>
                          <dt>Error code</dt>
                          <dd>
                            <code>{detail.errorCode}</code>
                          </dd>
                        </div>
                      ) : null}
                    </dl>
                    {detail.diff && detail.diff.length > 0 ? <DiffTable diff={detail.diff} label="Audit diff" /> : null}
                  </div>
                  <div role="tabpanel" id="audit-panel-raw" aria-labelledby="audit-tab-raw" hidden={tab !== "raw"}>
                    <pre className="raw" aria-label="Raw audit event JSON">
                      {JSON.stringify(detail, null, 2)}
                    </pre>
                  </div>
                </>
              ) : null}
            </div>
          </section>
        </div>
      )}
    </main>
  );
}
