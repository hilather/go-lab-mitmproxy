import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  deleteFlow,
  errorMessage,
  downloadFlowBody,
  flowBodyFilename,
  getFlow,
  requestBodyURL,
  responseBodyURL,
  type FlowBodySide,
} from "../api/client";
import type { Flow, GRPCMessage, Header, HTTPMessage, ProtoField, WebSocketFrame } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_WRITE, formatBytes } from "../auth/scopes";
import {
  TUNNEL_REASON,
  flowAuthority,
  isTunnelNotDecrypt,
  listTimingLabel,
  tunnelSubtitle,
} from "../ui/flowKind";
import { contentTypeOf, shouldRenderAsText, toHexDump } from "../ui/bodyView";
import { useConfirm } from "../ui/ConfirmDialog";
import { localTime } from "../ui/time";

import { FlowActions } from "./FlowActions";

type Tab = "request" | "response" | "trailers" | "tls" | "frames" | "grpc" | "raw";

function FlowCaptureMeta({ flow }: { flow: Flow }) {
  const socksDest = flow.socks?.dest ?? "";
  const hasMeta =
    flow.http2 != null || (flow.via ?? "") !== "" || socksDest !== "" || (flow.originalDest ?? "") !== "";
  if (!hasMeta) {
    return null;
  }
  return (
    <dl>
      {flow.http2 != null ? (
        <div>
          <dt>Stream ID</dt>
          <dd>{flow.http2.streamId}</dd>
        </div>
      ) : null}
      {flow.http2?.pushed ? (
        <div>
          <dt>Pushed</dt>
          <dd>
            yes (parent {flow.http2.parentStreamId}, promised {flow.http2.promisedId})
          </dd>
        </div>
      ) : null}
      {flow.via ? (
        <div>
          <dt>Via</dt>
          <dd>{flow.via}</dd>
        </div>
      ) : null}
      {socksDest !== "" ? (
        <div>
          <dt>SOCKS dest</dt>
          <dd>{socksDest}</dd>
        </div>
      ) : null}
      {flow.originalDest ? (
        <div>
          <dt>Original dest</dt>
          <dd>{flow.originalDest}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function TrailersPanel({ request, response }: { request: HTTPMessage; response: HTTPMessage }) {
  const req = request.trailers ?? [];
  const resp = response.trailers ?? [];
  if (req.length === 0 && resp.length === 0) {
    return <p>No trailers.</p>;
  }
  return (
    <>
      <h2>Request trailers</h2>
      {req.length === 0 ? <p>No request trailers.</p> : <HeadersTable headers={req} />}
      <h2>Response trailers</h2>
      {resp.length === 0 ? <p>No response trailers.</p> : <HeadersTable headers={resp} />}
    </>
  );
}

function HeadersTable({ headers }: { headers: Header[] }) {
  if (headers.length === 0) {
    return <p>No headers.</p>;
  }
  return (
    <table className="data">
      <thead>
        <tr>
          <th>Name</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {headers.map((h, i) => (
          <tr key={`${h.name}-${i}`}>
            <td>{h.name}</td>
            <td>{h.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function FramePayload({ frame }: { frame: WebSocketFrame }) {
  const body = frame.payload ?? "";
  if (body === "" && frame.size === 0) {
    return <p className="muted">Empty payload.</p>;
  }
  if (shouldRenderAsText("", body)) {
    return <pre className="raw">{body || "(empty)"}</pre>;
  }
  return (
    <>
      <p className="muted">
        Binary payload. Showing hex preview of {formatBytes(body.length)}
        {frame.size > 0 && frame.size !== body.length ? ` (reported ${formatBytes(frame.size)})` : ""}.
      </p>
      <pre className="raw">{toHexDump(body)}</pre>
    </>
  );
}

function FramesPanel({ flow }: { flow: Flow }) {
  const frames = flow.websocket?.frames ?? [];
  if (flow.websocket == null) {
    return <p>No WebSocket frames.</p>;
  }
  if (frames.length === 0) {
    return (
      <p className="muted">
        {flow.websocket.frameCount} frame{flow.websocket.frameCount === 1 ? "" : "s"} counted
        {flow.websocket.truncated ? " · truncated" : ""}; none stored on this GET.
      </p>
    );
  }
  return (
    <>
      <p className="muted">
        {flow.websocket.frameCount} frame{flow.websocket.frameCount === 1 ? "" : "s"}
        {flow.websocket.truncated ? " · truncated" : ""}
      </p>
      {frames.map((fr, i) => (
        <section key={`${fr.opcode}-${i}`}>
          <h2>
            {fr.direction} · {fr.opcode}
            {fr.closeCode ? ` · ${fr.closeCode}` : ""}
            {fr.truncated ? " · truncated" : ""}
            {fr.masked ? " · masked" : ""}
            {fr.action === "drop" || fr.action === "block" ? (
              <>
                {" "}
                <span className="badge">{fr.action}</span>
              </>
            ) : null}
          </h2>
          <FramePayload frame={fr} />
        </section>
      ))}
    </>
  );
}

function ProtoFields({ fields }: { fields: ProtoField[] }) {
  if (fields.length === 0) {
    return <p className="muted">No fields.</p>;
  }
  return (
    <ul>
      {fields.map((f, i) => (
        <li key={`${f.number}-${i}`}>
          #{f.number} · wire {f.wireType}
          {f.uint !== undefined ? ` · ${f.uint}` : ""}
          {f.text ? <pre className="raw">{f.text}</pre> : null}
          {f.nested && f.nested.length > 0 ? <ProtoFields fields={f.nested} /> : null}
        </li>
      ))}
    </ul>
  );
}

function GRPCMessageView({ msg, index }: { msg: GRPCMessage; index: number }) {
  return (
    <section>
      <h2>
        message {index + 1}
        {msg.compressed ? " · compressed" : ""}
        {msg.length > 0 ? ` · ${msg.length} bytes` : ""}
      </h2>
      <ProtoFields fields={msg.fields ?? []} />
    </section>
  );
}

function GRPCPanel({ flow }: { flow: Flow }) {
  const grpc = flow.grpc;
  if (grpc == null) {
    return <p>No gRPC decode.</p>;
  }
  const messages = grpc.messages ?? [];
  return (
    <>
      <p className="muted">
        {grpc.contentType || "application/grpc"}
        {grpc.compressed ? " · compressed" : ""}
        {grpc.truncated ? " · truncated" : ""}
        {grpc.decodeError ? ` · ${grpc.decodeError}` : ""}
      </p>
      {messages.length === 0 ? (
        <p className="muted">No messages stored on this GET.</p>
      ) : (
        messages.map((m, i) => <GRPCMessageView key={i} msg={m} index={i} />)
      )}
    </>
  );
}

function MessageBody({ msg }: { msg: HTTPMessage }) {
  const ct = contentTypeOf(msg.headers);
  const body = msg.body ?? "";
  if (body === "" && msg.size === 0) {
    return <p className="muted">Empty body.</p>;
  }
  if (shouldRenderAsText(ct, body)) {
    return <pre className="raw">{body || "(empty)"}</pre>;
  }
  return (
    <>
      <p className="muted">
        Binary or non-text body{ct !== "" ? ` (${ct})` : ""}. Showing hex preview of{" "}
        {formatBytes(body.length)}
        {msg.size > 0 && msg.size !== body.length ? ` (reported ${formatBytes(msg.size)})` : ""}.
      </p>
      <pre className="raw">{toHexDump(body)}</pre>
    </>
  );
}

function requestPath(flow: Flow): string {
  const headers = flow.request.headers ?? [];
  for (const h of headers) {
    if (h.name === ":path") {
      return h.value;
    }
  }
  const raw = flow.url || "";
  if (raw === "") {
    return "/";
  }
  try {
    const u = new URL(raw);
    return `${u.pathname}${u.search}`;
  } catch {
    return raw;
  }
}

function formatMessageRaw(flow: Flow, side: "request" | "response"): string {
  const msg = side === "request" ? flow.request : flow.response;
  const headers = msg.headers ?? [];
  const proto = flow.protocol === "h2" ? "HTTP/2" : "HTTP/1.1";
  const lines: string[] = [];
  if (side === "request") {
    lines.push(`${flow.method || "GET"} ${requestPath(flow)} ${proto}`);
  } else {
    const status = flow.status > 0 ? String(flow.status) : flow.state;
    lines.push(`${proto} ${status}`);
  }
  for (const h of headers) {
    if (h.name.startsWith(":")) {
      continue;
    }
    lines.push(`${h.name}: ${h.value}`);
  }
  return lines.join("\n");
}

function protocolChip(protocol: string): string {
  if (protocol === "http/1.1") {
    return "HTTP/1.1";
  }
  return protocol || "?";
}

export function SelectFlowEmpty() {
  return (
    <div className="empty-state">
      <h2 className="empty-title">Select a captured flow.</h2>
      <p>Pick a row to open it here. Paused flows wait for Resume or Drop until their breakpoint timeout.</p>
    </div>
  );
}

function TunnelSummary({ flow }: { flow: Flow }) {
  return (
    <section className="tunnel-summary">
      <h2>Tunnel-not-decrypt</h2>
      <p>
        CONNECT {flowAuthority(flow)} · {tunnelSubtitle(flow)}
      </p>
      <p className="muted">{TUNNEL_REASON}</p>
    </section>
  );
}

export function FlowInspector({
  id,
  embedded,
  onDeleted,
  storeGeneration,
}: {
  id: string;
  embedded?: boolean;
  onDeleted?: () => void;
  storeGeneration?: number | undefined;
}) {
  const navigate = useNavigate();
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const loadedID = useRef("");
  const activeID = useRef(id);
  activeID.current = id;
  const [expectedGeneration, setExpectedGeneration] = useState("");
  // Read after the confirm resolves; the dialog edits it while onDelete awaits.
  const expectedGenerationRef = useRef(expectedGeneration);
  expectedGenerationRef.current = expectedGeneration;
  const [renderConfirm, confirm] = useConfirm();
  const expectedGenerationId = useId();
  const [actionsHost, setActionsHost] = useState<HTMLSpanElement | null>(null);
  const [refreshCounter, setRefreshCounter] = useState(0);
  const [tab, setTab] = useState<Tab>("request");
  const [flow, setFlow] = useState<Flow | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    if (loadedID.current !== id) {
      setTab("request");
      setExpectedGeneration("");
      setFlow(null);
      loadedID.current = id;
    }
    setError("");
    if (id === "") {
      return;
    }
    void (async () => {
      try {
        const next = await getFlow(id);
        if (!cancelled) {
          setFlow(next);
          setError("");
        }
      } catch (err) {
        if (!cancelled) {
          setError(errorMessage(err, "Flow not found."));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id, refreshCounter, storeGeneration]);

  async function onDelete() {
    const ok = await confirm({
      title: "Delete this flow?",
      body: <p>Removes this captured flow from the store. This cannot be undone.</p>,
      confirmLabel: "Delete",
      danger: true,
    });
    if (!ok || activeID.current !== id) {
      return;
    }
    try {
      const expected = expectedGenerationRef.current;
      await deleteFlow(id, expected === "" ? undefined : Number(expected));
      if (activeID.current !== id) return;
      if (onDeleted) {
        onDeleted();
      }
      void navigate("/", { replace: true });
    } catch (err) {
      if (activeID.current === id) setError(errorMessage(err, "Delete failed."));
    }
  }

  async function onDownload(side: FlowBodySide) {
    try {
      await downloadFlowBody(id, side);
    } catch (err) {
      if (activeID.current === id) setError(errorMessage(err, "Download failed."));
    }
  }

  const wrap = (node: ReactNode) =>
    embedded ? <div className="inspector">{node}</div> : <main className="page">{node}</main>;

  if (id === "") {
    return wrap(<SelectFlowEmpty />);
  }
  if (error !== "" && flow === null) {
    return wrap(
      <>
        <p className="banner-error" role="alert">
          {error}
        </p>
        {embedded ? null : (
          <p>
            <Link to="/">Back to flows</Link>
          </p>
        )}
      </>,
    );
  }
  if (flow === null) {
    return wrap(
      <p role="status">Loading flow…</p>,
    );
  }

  const tunnel = isTunnelNotDecrypt(flow);
  const tabs: { id: Tab; label: string }[] = [
    { id: "request", label: "Request" },
    { id: "response", label: "Response" },
    { id: "tls", label: "TLS" },
  ];
  const hasTrailers =
    (flow.request.trailers ?? []).length > 0 || (flow.response.trailers ?? []).length > 0;
  if (!tunnel && hasTrailers) {
    tabs.splice(2, 0, { id: "trailers", label: "Trailers" });
  }
  if (flow.websocket != null) {
    tabs.push({ id: "frames", label: "Frames" });
  }
  if (flow.grpc != null) {
    tabs.push({ id: "grpc", label: "gRPC" });
  }
  tabs.push({ id: "raw", label: "Raw JSON" });
  const paused = flow.state === "paused";

  const title = flow.url !== "" ? `${flow.method} ${flow.url}` : `${flow.method} ${flowAuthority(flow)}`;

  return wrap(
    <>
      {embedded ? null : (
        <p>
          <Link to="/">Flows</Link>
        </p>
      )}
      <div className="inspector-head">
        <div className="inspector-title">
          <h1 className="mono">{title}</h1>
          <p className="inspector-summary">
            {flow.status > 0 ? flow.status : flow.state}
            {paused && flow.pausedPhase ? ` · ${flow.pausedPhase} phase` : ""} · {listTimingLabel(flow)} ·{" "}
            {formatBytes(flow.requestBytes)} in · {formatBytes(flow.responseBytes)} out
            {flow.startedAt ? (
              <>
                {" "}
                · started <time dateTime={flow.startedAt} title={flow.startedAt}>{localTime(flow.startedAt)}</time>
              </>
            ) : null}
          </p>
          <p className="chip-row">
            {paused ? (
              <span className="chip chip-accent chip-fill">
                paused{flow.pausedPhase ? ` · ${flow.pausedPhase}` : ""}
              </span>
            ) : null}
            <span className="badge">{protocolChip(flow.protocol)}</span>
            {flow.http2 != null ? <span className="badge">stream {flow.http2.streamId}</span> : null}
            {flow.websocket != null ? <span className="badge">{flow.websocket.frameCount} frames</span> : null}
            {flow.grpc != null ? <span className="badge">grpc</span> : null}
            {(flow.ruleIds ?? []).map((rule) => (
              <span key={rule} className="chip" title={`rule ${rule}`}>
                rule {rule}
              </span>
            ))}
            {flow.intercepted ? <span className="chip chip-accent">intercepted</span> : null}
            {tunnel ? <span className="chip chip-tunnel">tunnel-not-decrypt</span> : null}
            {flow.truncated ? <span className="badge">truncated</span> : null}
          </p>
        </div>
        <div className="inspector-actions">
          <span ref={setActionsHost} style={{ display: "contents" }} />
          {canWrite ? (
            <button type="button" className="btn-danger" onClick={() => void onDelete()}>
              Delete<span aria-hidden="true">…</span>
            </button>
          ) : null}
        </div>
      </div>
      <FlowActions
        key={flow.id}
        flow={flow}
        replayHost={actionsHost}
        onChanged={() => {
          if (activeID.current === flow.id) setRefreshCounter((n) => n + 1);
        }}
      />
      <FlowCaptureMeta flow={flow} />
      {flow.error ? <p className="banner-error">{flow.error}</p> : null}
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="tabs" role="tablist" aria-label="Flow parts">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "request" ? (
        tunnel ? (
          <TunnelSummary flow={flow} />
        ) : (
          <>
            <p>
              <a
                href={requestBodyURL(flow.id)}
                download={flowBodyFilename(flow.id, "request")}
                onClick={(ev) => {
                  ev.preventDefault();
                  void onDownload("request");
                }}
              >
                Download request body
              </a>
            </p>
            <div className="msg-grid">
              <pre className="raw">{formatMessageRaw(flow, "request")}</pre>
              <div>
                <MessageBody msg={flow.request} />
              </div>
            </div>
          </>
        )
      ) : null}
      {tab === "response" ? (
        tunnel ? (
          <TunnelSummary flow={flow} />
        ) : (
          <>
            <p>
              <a
                href={responseBodyURL(flow.id)}
                download={flowBodyFilename(flow.id, "response")}
                onClick={(ev) => {
                  ev.preventDefault();
                  void onDownload("response");
                }}
              >
                Download response body
              </a>
            </p>
            <div className="msg-grid">
              <pre className="raw">{formatMessageRaw(flow, "response")}</pre>
              <div>
                <MessageBody msg={flow.response} />
              </div>
            </div>
          </>
        )
      ) : null}
      {tab === "trailers" ? <TrailersPanel request={flow.request} response={flow.response} /> : null}
      {tab === "frames" ? <FramesPanel flow={flow} /> : null}
      {tab === "grpc" ? <GRPCPanel flow={flow} /> : null}
      {tab === "raw" ? (
        <pre className="raw" aria-label="Complete flow JSON">
          {JSON.stringify(flow, null, 2)}
        </pre>
      ) : null}
      {tab === "tls" ? (
        flow.tls ? (
          <dl>
            <div>
              <dt>SNI</dt>
              <dd>{flow.tls.sni || "—"}</dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>{flow.tls.version || "—"}</dd>
            </div>
            <div>
              <dt>Cipher</dt>
              <dd>{flow.tls.cipherSuite || "—"}</dd>
            </div>
            <div>
              <dt>ALPN</dt>
              <dd>{flow.tls.alpn || "—"}</dd>
            </div>
            <div>
              <dt>Upstream verified</dt>
              <dd>{flow.tls.upstreamVerified ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt>Leaf DNS</dt>
              <dd>{(flow.tls.leafDns ?? []).join(", ") || "—"}</dd>
            </div>
          </dl>
        ) : (
          <p>No TLS metadata. Cleartext hop or intercept did not run.</p>
        )
      ) : null}
      {renderConfirm(
        canWrite ? (
          <>
            <label htmlFor={expectedGenerationId}>Delete expected store generation (optional)</label>
            <input
              id={expectedGenerationId}
              type="number"
              min="0"
              step="1"
              placeholder={storeGeneration === undefined ? "Any generation" : `Current ${storeGeneration}`}
              value={expectedGeneration}
              onChange={(e) => setExpectedGeneration(e.target.value)}
            />
          </>
        ) : null,
      )}
    </>,
  );
}
