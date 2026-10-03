import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, dropFlow, replayFlow, resumeFlow } from "../api/client";
import type { Flow, Header } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE } from "../auth/scopes";

export function FlowActions({
  flow,
  onChanged,
}: {
  flow: Flow;
  onChanged: () => void;
}) {
  const { hasScope } = useAuth();
  const [headersEnabled, setHeadersEnabled] = useState(false);
  const [bodyEnabled, setBodyEnabled] = useState(false);
  const [headers, setHeaders] = useState<Header[]>([]);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Flow | null>(null);
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
      const warning =
        kind === "drop"
          ? "Drop this paused flow and close its exchange?"
          : "Replay this captured request once against its origin?";
      if (!window.confirm(warning)) return;
    }
    busyRef.current = true;
    setBusy(true);
    setError("");
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
      if (mounted.current)
        setError(
          err instanceof APIError
            ? JSON.stringify(err.problem, null, 2)
            : err instanceof Error
              ? err.message
              : "Flow action failed.",
        );
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

  return (
    <section aria-label="Flow actions">
      {flow.state === "paused" ? (
        <>
          <h2>Paused {flow.pausedPhase || "exchange"}</h2>
          <p>
            Unchecked edits preserve the original. Checked empty fields
            explicitly clear headers or body.
          </p>
          <label>
            <input
              type="checkbox"
              checked={headersEnabled}
              onChange={(event) => setHeadersEnabled(event.target.checked)}
            />
            Replace headers
          </label>
          {headersEnabled ? (
            <div>
              {headers.map((header, index) => (
                <div key={index}>
                  <label>
                    Header name {index + 1}
                    <input
                      value={header.name}
                      onChange={(event) =>
                        editHeader(index, "name", event.target.value)
                      }
                    />
                  </label>
                  <label>
                    Header value {index + 1}
                    <input
                      value={header.value}
                      onChange={(event) =>
                        editHeader(index, "value", event.target.value)
                      }
                    />
                  </label>
                  <button
                    type="button"
                    onClick={() =>
                      setHeaders(
                        headers.filter((_, current) => current !== index),
                      )
                    }
                  >
                    Remove header {index + 1}
                  </button>
                </div>
              ))}
              <button type="button" onClick={copyHeaders}>
                Copy captured headers
              </button>
              <button type="button" onClick={() => setHeaders([])}>
                Clear replacement headers
              </button>
              <button
                type="button"
                onClick={() =>
                  setHeaders([...headers, { name: "", value: "" }])
                }
              >
                Add header
              </button>
            </div>
          ) : null}
          <label>
            <input
              type="checkbox"
              checked={bodyEnabled}
              onChange={(event) => setBodyEnabled(event.target.checked)}
            />
            Replace body
          </label>
          {bodyEnabled ? (
            <label>
              Replacement body
              <textarea
                value={body}
                onChange={(event) => setBody(event.target.value)}
              />
            </label>
          ) : null}
          <button disabled={busy} onClick={() => void act("resume")}>
            Resume flow
          </button>
          <button disabled={busy} onClick={() => void act("drop")}>
            Drop flow
          </button>
        </>
      ) : null}
      <button disabled={busy} onClick={() => void act("replay")}>
        Replay flow
      </button>
      {busy ? <p role="status">Flow action pending…</p> : null}
      {error ? (
        <pre className="banner-error" role="alert">
          {error}
        </pre>
      ) : null}
      {result ? (
        <section aria-label="Replay result">
          <h2>Replay result</h2>
          <Link to={`/flows/${encodeURIComponent(result.id)}`}>
            Inspect replay {result.id}
          </Link>
          <p>
            {result.method} {result.url} · {result.status || result.state}
          </p>
          <pre className="raw">{JSON.stringify(result, null, 2)}</pre>
        </section>
      ) : null}
    </section>
  );
}
