import { useEffect, useState } from "react";
import { APIError, listAudit } from "../api/client";
import type { AuditEvent } from "../api/types";

export function AuditPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const list = await listAudit();
        setEvents(list.events ?? []);
      } catch (err) {
        setError(err instanceof APIError ? err.message : "Could not load audit.");
      }
    })();
  }, []);

  if (error !== "") {
    return (
      <main className="page">
        <p className="banner-error" role="alert">
          {error}
        </p>
      </main>
    );
  }
  if (events === null) {
    return (
      <main className="page">
        <p role="status">Loading audit…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Audit</h1>
      <p className="muted">Scoped to mitm.audit.read. Bodies and secrets are not recorded.</p>
      {events.length === 0 ? (
        <p>No audit events.</p>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>Time</th>
              <th>Capability</th>
              <th>Actor</th>
              <th>Result</th>
              <th>Flow</th>
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
                <td>
                  <code>{ev.flowId ?? ev.id}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
