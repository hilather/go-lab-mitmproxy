import { useEffect, useRef, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { getAudit, queryAudit, type FullAuditEvent } from "../api/diagnostics";
import type { AuditEvent } from "../api/types";
export function AuditPage() {
  const auth = useAuth();
  const actorID =
    auth.state.status === "signed_in" ? auth.state.session.id : "";
  const permitted = auth.hasScope("mitm.audit.read");
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [limit, setLimit] = useState("");
  const [eventId, setEventId] = useState("");
  const [detail, setDetail] = useState<FullAuditEvent>();
  const [error, setError] = useState("");
  const [detailError, setDetailError] = useState("");
  const [loading, setLoading] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
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
      if (mine === generation.current)
        setError(err instanceof Error ? err.message : "Could not load audit.");
    } finally {
      if (mine === generation.current) setLoading(false);
    }
  }
  async function lookup(id: string) {
    const mine = ++detailGeneration.current;
    setEventId(id);
    setDetail(undefined);
    setDetailError("");
    setDetailLoading(true);
    try {
      const ev = await getAudit(id);
      if (mine === detailGeneration.current) setDetail(ev);
    } catch (err) {
      if (mine === detailGeneration.current)
        setDetailError(
          err instanceof Error ? err.message : "Could not load audit event.",
        );
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
  return (
    <main className="page">
      <p className="kicker">Audit</p>
      <h1>Audit</h1>
      {auth.state.status === "loading" ? (
        <p role="status">Loading session…</p>
      ) : !permitted ? (
        <p role="alert">Audit requires mitm.audit.read.</p>
      ) : (
        <>
          <p className="muted">
            Scoped to mitm.audit.read. Bodies and secrets are not recorded.
          </p>
          <form
            onSubmit={(ev) => {
              ev.preventDefault();
              void refresh();
            }}
          >
            <label>
              Limit
              <input
                type="number"
                min="0"
                step="1"
                value={limit}
                onChange={(ev) => setLimit(ev.target.value)}
              />
            </label>
            <p className="muted">
              Leave blank or use 0 for the latest 100 events. The server caps
              results at 100.
            </p>
            <button disabled={loading}>Refresh audit</button>
          </form>
          {loading ? (
            <p role="status">Loading audit…</p>
          ) : error ? (
            <p role="alert">{error}</p>
          ) : events.length === 0 ? (
            <div className="panel">
              <p>No audit events.</p>
            </div>
          ) : (
            <div className="panel">
              <table className="data">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Capability</th>
                    <th>Actor</th>
                    <th>Result</th>
                    <th>Flow</th>
                    <th>Event</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => (
                    <tr key={ev.id}>
                      <td>{ev.time}</td>
                      <td>{ev.capability ?? "—"}</td>
                      <td>
                        {ev.actorId ?? "—"}
                        {ev.transport ? ` (${ev.transport})` : ""}
                      </td>
                      <td>{ev.result ?? "—"}</td>
                      <td>{ev.flowId ?? "—"}</td>
                      <td>
                        <button onClick={() => void lookup(ev.id)}>
                          {ev.id}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <section className="panel" aria-label="Audit event detail">
            <h2>Audit event detail</h2>
            <form
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
              <button disabled={detailLoading || eventId === ""}>
                Find event
              </button>
            </form>
            {detailLoading && <p role="status">Loading audit event…</p>}
            {detailError && <p role="alert">{detailError}</p>}
            {detail && <pre>{JSON.stringify(detail, null, 2)}</pre>}
          </section>
        </>
      )}
    </main>
  );
}
