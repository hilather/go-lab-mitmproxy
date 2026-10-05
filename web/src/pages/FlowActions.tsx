import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { dropFlow, replayFlow, resumeFlow } from "../api/client";
import type { Flow, Header } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE } from "../auth/scopes";
import { useConfirm } from "../ui/ConfirmDialog";
import { ProblemBanner } from "../ui/ProblemBanner";

export function FlowActions({
  flow,
  onChanged,
  replayHost = null,
}: {
  flow: Flow;
  onChanged: () => void;
  /** Inspector-head slot for the Replay trigger; state and result stay here. */
  replayHost?: HTMLElement | null;
}) {
  const { hasScope } = useAuth();
  const [headersEnabled, setHeadersEnabled] = useState(false);
  const [bodyEnabled, setBodyEnabled] = useState(false);
  const [headers, setHeaders] = useState<Header[]>([]);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<Flow | null>(null);
  const [renderConfirm, confirm] = useConfirm();
  const mounted = useRef(true);
  const busyRef = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  if (!hasScope(SCOPE_WRITE)) return null;

  async function act(kind: "resume" | "drop" | "replay") {
    if (busyRef.current) return;
    if (kind !== "resume") {
      const ok = await confirm(
        kind === "drop"
          ? {
              title: "Drop this paused flow and close its exchange?",
              body: <p>The client connection is closed without forwarding. This cannot be undone.</p>,
              confirmLabel: "Drop flow",
              danger: true,
            }
          : {
              title: "Replay this captured request once against its origin?",
              body: <p>Sends one request through the guarded replay operation and records a new flow.</p>,
              confirmLabel: "Replay flow",
            },
      );
      if (!ok || busyRef.current) return;
    }
    busyRef.current = true;
    setBusy(true);
    setError(null);
    try {
      if (kind === "resume") {
        await resumeFlow(flow.id, {
          ...(headersEnabled ? { headers } : {}),
          ...(bodyEnabled ? { body } : {}),
        });
      }
      if (kind === "drop") await dropFlow(flow.id);
      if (kind === "replay") {
        const replayed = await replayFlow(flow.id);
        if (mounted.current) setResult(replayed);
      }
      if (mounted.current && kind !== "replay") onChanged();
    } catch (err) {
      if (mounted.current) setError(err ?? new Error("Flow action failed."));
    } finally {
      busyRef.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  function editHeader(index: number, field: "name" | "value", value: string) {
    setHeaders(
      headers.map((header, current) =>
        current === index ? { ...header, [field]: value } : header,
      ),
    );
  }

  function copyHeaders() {
    const message =
      flow.pausedPhase === "response" ? flow.response : flow.request;
    setHeaders(message.headers?.map((header) => ({ ...header })) ?? []);
  }

  const phase = flow.pausedPhase || "exchange";
  const replayButton = (
    <button type="button" disabled={busy} onClick={() => void act("replay")}>
      Replay flow<span aria-hidden="true">…</span>
    </button>
  );

  return (
    <section aria-label="Flow actions" className="flow-actions">
      {replayHost ? createPortal(replayButton, replayHost) : replayButton}
      {flow.state === "paused" ? (
        <div className="bp-card">
          <div className="card-h">
            <h2>Breakpoint · paused {phase}</h2>
            <span className="hint">Unchanged sections forward exactly as captured.</span>
          </div>
          <div className="card-b bp-grid">
            <div>
              <div className="list-head-row">
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={headersEnabled}
                    onChange={(event) => setHeadersEnabled(event.target.checked)}
                  />
                  Replace headers
                </label>
                <span className="hint mono">
                  {headersEnabled ? `replacing · ${headers.length} rows` : "keeping captured"}
                </span>
              </div>
              {headersEnabled ? (
                <div style={{ marginTop: "0.5rem" }}>
                  {headers.map((header, index) => (
                    <div className="header-row" key={index}>
                      <input
                        aria-label={`Header name ${index + 1}`}
                        value={header.name}
                        onChange={(event) =>
                          editHeader(index, "name", event.target.value)
                        }
                      />
                      <input
                        aria-label={`Header value ${index + 1}`}
                        value={header.value}
                        onChange={(event) =>
                          editHeader(index, "value", event.target.value)
                        }
                      />
                      <button
                        type="button"
                        className="btn-sm btn-ghost"
                        aria-label={`Remove header ${index + 1}`}
                        onClick={() =>
                          setHeaders(
                            headers.filter((_, current) => current !== index),
                          )
                        }
                      >
                        ×
                      </button>
                    </div>
                  ))}
                  {headers.length === 0 ? (
                    <p className="hint">On with no rows sends an empty header list.</p>
                  ) : null}
                  <div className="actions">
                    <button
                      type="button"
                      className="btn-sm"
                      onClick={() =>
                        setHeaders([...headers, { name: "", value: "" }])
                      }
                    >
                      Add header
                    </button>
                    <button type="button" className="btn-sm" onClick={copyHeaders}>
                      Copy captured headers
                    </button>
                    <button type="button" className="btn-sm" onClick={() => setHeaders([])}>
                      Clear replacement headers
                    </button>
                  </div>
                </div>
              ) : (
                <p className="hint">Off keeps the captured headers.</p>
              )}
            </div>
            <div>
              <div className="list-head-row">
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={bodyEnabled}
                    onChange={(event) => setBodyEnabled(event.target.checked)}
                  />
                  Replace body
                </label>
                <span className="hint mono">{bodyEnabled ? "replacing" : "keeping captured"}</span>
              </div>
              {bodyEnabled ? (
                <textarea
                  rows={5}
                  aria-label="Replacement body"
                  style={{ marginTop: "0.5rem" }}
                  value={body}
                  onChange={(event) => setBody(event.target.value)}
                />
              ) : null}
              <p className="note" style={{ marginTop: "0.5rem" }}>
                <span className="mono">i</span>
                <span>On with an empty body clears the body. Off keeps the captured body.</span>
              </p>
            </div>
          </div>
          <div className="bp-foot">
            <button type="button" className="primary" disabled={busy} onClick={() => void act("resume")}>
              Resume flow
            </button>
            <button type="button" className="btn-danger" disabled={busy} onClick={() => void act("drop")}>
              Drop flow<span aria-hidden="true">…</span>
            </button>
            <p className="hint">
              {flow.pausedPhase === "request" ? (
                <>
                  Request-phase resume forwards a completed capture under a <strong>new ID</strong>. This record stays
                  open.{" "}
                </>
              ) : flow.pausedPhase === "response" ? (
                <>Response-phase resume completes this record. </>
              ) : null}
              Drop closes the exchange.
            </p>
          </div>
        </div>
      ) : null}
      {busy ? <p role="status">Flow action pending…</p> : null}
      <ProblemBanner error={error} fallback="Flow action failed." />
      {result ? (
        <section aria-label="Replay result" className="card">
          <div className="card-h">
            <h2>Replay result</h2>
            <Link to={`/flows/${encodeURIComponent(result.id)}`}>
              Inspect replay {result.id}
            </Link>
          </div>
          <div className="card-b">
            <p className="mono">
              {result.method} {result.url} · {result.status || result.state}
            </p>
            <details>
              <summary>Complete replayed flow JSON</summary>
              <pre className="raw">{JSON.stringify(result, null, 2)}</pre>
            </details>
          </div>
        </section>
      ) : null}
      {renderConfirm()}
    </section>
  );
}
