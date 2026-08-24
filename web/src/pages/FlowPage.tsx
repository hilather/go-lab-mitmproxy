import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  APIError,
  deleteFlow,
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
import { contentTypeOf, shouldRenderAsText, toHexDump } from "../ui/bodyView";

type Tab = "request" | "response" | "trailers" | "tls" | "frames" | "grpc";

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

export function FlowPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const { hasScope } = useAuth();
  const canWrite = hasScope(SCOPE_WRITE);
  const [tab, setTab] = useState<Tab>("request");
  const [flow, setFlow] = useState<Flow | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const next = await getFlow(id);
        if (!cancelled) {
          setFlow(next);
          setError("");
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Flow not found.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  async function onDelete() {
    if (!window.confirm("Delete this flow?")) {
      return;
    }
    try {
      await deleteFlow(id);
      void navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof APIError ? err.message : "Delete failed.");
    }
  }

  async function onDownload(side: FlowBodySide) {
    try {
      await downloadFlowBody(id, side);
    } catch (err) {
      setError(err instanceof APIError ? err.message : "Download failed.");
    }
  }

  if (error !== "" && flow === null) {
    return (
      <main className="page">
        <p className="banner-error" role="alert">
          {error}
        </p>
        <p>
          <Link to="/">Back to flows</Link>
        </p>
      </main>
    );
  }
  if (flow === null) {
    return (
      <main className="page">
        <p role="status">Loading flow…</p>
      </main>
    );
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "request", label: "Request" },
    { id: "response", label: "Response" },
    { id: "trailers", label: "Trailers" },
    { id: "tls", label: "TLS" },
  ];
  if (flow.websocket != null) {
    tabs.push({ id: "frames", label: "Frames" });
  }
  if (flow.grpc != null) {
    tabs.push({ id: "grpc", label: "gRPC" });
  }

  return (
    <main className="page">
      <p>
        <Link to="/">Flows</Link>
      </p>
      <h1>
        {flow.method} {flow.url}
      </h1>
      <p>
        {flow.status > 0 ? `HTTP ${flow.status}` : flow.state} · {flow.host} · {flow.scheme}{" "}
        <span className="badge">{flow.protocol || "?"}</span>
        {flow.http2 != null ? <span className="badge">stream {flow.http2.streamId}</span> : null}
        {flow.websocket != null ? <span className="badge">{flow.websocket.frameCount} frames</span> : null}
        {flow.grpc != null ? <span className="badge">grpc</span> : null}
        {flow.intercepted ? " · intercepted" : ""}
        {flow.truncated ? " · truncated" : ""}
      </p>
      <p className="muted">
        {formatBytes(flow.requestBytes)} request · {formatBytes(flow.responseBytes)} response
        {flow.clientAddr ? ` · ${flow.clientAddr}` : ""}
        {flow.ruleIds && flow.ruleIds.length > 0 ? ` · rules ${flow.ruleIds.join(", ")}` : ""}
      </p>
      <FlowCaptureMeta flow={flow} />
      {flow.error ? <p className="banner-error">{flow.error}</p> : null}
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      {canWrite ? (
        <p>
          <button type="button" onClick={() => void onDelete()}>
            Delete flow
          </button>
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
          <HeadersTable headers={flow.request.headers ?? []} />
          <MessageBody msg={flow.request} />
        </>
      ) : null}
      {tab === "response" ? (
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
          <HeadersTable headers={flow.response.headers ?? []} />
          <MessageBody msg={flow.response} />
        </>
      ) : null}
      {tab === "trailers" ? <TrailersPanel request={flow.request} response={flow.response} /> : null}
      {tab === "frames" ? <FramesPanel flow={flow} /> : null}
      {tab === "grpc" ? <GRPCPanel flow={flow} /> : null}
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
    </main>
  );
}
