import { useEffect, useRef, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { errorMessage } from "../api/client";
import {
  diagnosticReads,
  getDiagnostic,
  type DiagnosticRead,
} from "../api/diagnostics";
function DiagnosticPanel({ read }: { read: DiagnosticRead }) {
  const generation = useRef(0);
  const [result, setResult] = useState<unknown>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  async function refresh() {
    const mine = ++generation.current;
    setLoading(true);
    setError("");
    setResult(undefined);
    try {
      const value = await getDiagnostic(read);
      if (generation.current === mine) setResult(value);
    } catch (err) {
      if (generation.current === mine)
        setError(
          errorMessage(err, "Could not load diagnostics.", true),
        );
    } finally {
      if (generation.current === mine) setLoading(false);
    }
  }
  useEffect(() => {
    void refresh();
    return () => {
      generation.current++;
    };
  }, []);
  return (
    <section className="panel" aria-label={read.title}>
      <h2>{read.title}</h2>
      <button disabled={loading} onClick={() => void refresh()}>
        Refresh {read.title}
      </button>
      {loading && <p role="status">Loading {read.title}…</p>}
      {error && <p role="alert">{error}</p>}
      {result !== undefined && (
        <pre className="raw diagnostic-output">
          {typeof result === "string"
            ? result
            : JSON.stringify(result, null, 2)}
        </pre>
      )}
      {read.id === "schema.get" && (
        <a href={read.path} download="labmitm-config.schema.json">
          Download configuration schema
        </a>
      )}
      {read.id === "metrics.get" && (
        <p className="muted">
          Management metrics require observability.metrics.publicPath. Enable it
          in bootstrap and restart the service if disabled.
        </p>
      )}
    </section>
  );
}
export function DiagnosticsPage() {
  const auth = useAuth();
  return (
    <main className="page">
      <p className="kicker">Diagnostics</p>
      <h1>Diagnostics</h1>
      {auth.state.status === "loading" ? (
        <p role="status">Loading session…</p>
      ) : !auth.hasScope("mitm.read") ? (
        <p role="alert">Diagnostics require mitm.read.</p>
      ) : (
        diagnosticReads.map((read) => (
          <DiagnosticPanel key={read.id} read={read} />
        ))
      )}
    </main>
  );
}
