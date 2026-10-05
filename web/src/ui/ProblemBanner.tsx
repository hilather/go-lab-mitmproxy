import { APIError, problemMessage } from "../api/client";

/**
 * ProblemBanner renders an action error. API problems keep every field the
 * old raw-JSON banner exposed: detail, violations and remediation in the
 * line, code/currentRevision/retryable as chips, and the raw problem one
 * click away. Other errors show their message.
 */
export function ProblemBanner({ error, fallback, suffix }: { error: unknown; fallback: string; suffix?: string }) {
  if (error === null || error === undefined) return null;
  if (error instanceof APIError) {
    const p = error.problem;
    return (
      <div className="banner-error problem" role="alert">
        <p>
          {problemMessage(p)}
          {suffix ? ` ${suffix}` : ""}
        </p>
        <p className="problem-meta">
          {p.code ? <span className="chip chip-danger">code {p.code}</span> : null}
          {p.status ? <span className="chip">HTTP {p.status}</span> : null}
          {p.currentRevision ? (
            <span className="chip wrap-anywhere" title={p.currentRevision}>
              current revision {p.currentRevision}
            </span>
          ) : null}
          {p.retryable !== undefined ? <span className="chip">retryable {String(p.retryable)}</span> : null}
        </p>
        <details>
          <summary>Raw problem JSON</summary>
          <pre className="raw">{JSON.stringify(p, null, 2)}</pre>
        </details>
      </div>
    );
  }
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : fallback;
  return (
    <p className="banner-error" role="alert">
      {message || fallback}
      {suffix ? ` ${suffix}` : ""}
    </p>
  );
}
