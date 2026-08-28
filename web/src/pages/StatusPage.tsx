import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { APIError, applyChanges, CA_DOWNLOAD_URL, getFeatures, getStatus } from "../api/client";
import type { Feature, FeatureList, Status } from "../api/types";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_ADMIN, formatBytes } from "../auth/scopes";

const FEATURE_UI_ENABLED = "ui.enabled";

function featureToggleable(feature: Feature, isAdmin: boolean): boolean {
  // Toggling ui.enabled from Status 404s the SPA with no in-browser way back.
  return (
    isAdmin &&
    feature.applyMode === "live" &&
    feature.verb === "setFeature" &&
    feature.id !== FEATURE_UI_ENABLED
  );
}

export function StatusPage() {
  const { hasScope } = useAuth();
  const canAdmin = hasScope(SCOPE_ADMIN);
  const [status, setStatus] = useState<Status | null>(null);
  const [features, setFeatures] = useState<FeatureList | null>(null);
  const [revision, setRevision] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [featureError, setFeatureError] = useState("");
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const st = await getStatus();
        if (!cancelled) {
          setStatus(st);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof APIError ? err.message : "Could not load status.");
        }
      }
    })();
    void (async () => {
      try {
        const list = await getFeatures();
        if (!cancelled) {
          setFeatures(list);
          setRevision(list.runtimeRevision);
        }
      } catch (err) {
        if (!cancelled) {
          setFeatureError(err instanceof APIError ? err.message : "Could not load features.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function refreshFeatures(): Promise<void> {
    const list = await getFeatures();
    setFeatures(list);
    if (list.runtimeRevision !== "") {
      setRevision(list.runtimeRevision);
    }
  }

  async function onToggle(feature: Feature) {
    if (!featureToggleable(feature, canAdmin) || busyRef.current) {
      return;
    }
    busyRef.current = true;
    setBusy(true);
    setFeatureError("");
    const idempotencyKey = crypto.randomUUID();
    try {
      const result = await applyChanges({
        expectedRevision: revision,
        idempotencyKey,
        reason: reason.trim(),
        operations: [
          {
            op: "setFeature",
            feature: { id: feature.id, enabled: !feature.enabled },
          },
        ],
      });
      if (result.runtimeRevision) {
        setRevision(result.runtimeRevision);
      }
      await refreshFeatures();
    } catch (err) {
      const detail =
        err instanceof APIError ? err.problem.detail || err.message : "Could not apply feature change.";
      setFeatureError(detail);
      if (err instanceof APIError && err.problem.status === 409) {
        try {
          await refreshFeatures();
        } catch {
          // Keep the apply problem+json detail.
        }
      }
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  if (error !== "") {
    return (
      <main className="page">
        <p className="banner-error" role="alert">
          {error}
        </p>
      </main>
    );
  }
  if (status === null) {
    return (
      <main className="page">
        <p role="status">Loading status…</p>
      </main>
    );
  }

  return (
    <main className="page">
      <h1>Status</h1>
      <p className="banner-warn">
        Lab-only intercepting proxy. Install the lab CA only on systems under test and uninstall it
        after use. LabMITM is not a public MITM product.
      </p>
      <p>
        Ready: <strong>{status.ready ? "yes" : "no"}</strong>
        {" · "}
        Intercept: <strong>{status.intercept ? "on" : "off"}</strong>
      </p>
      <h2>Lab CA</h2>
      <dl>
        <div>
          <dt>Mode</dt>
          <dd>{status.ca.mode || "—"}</dd>
        </div>
        <div>
          <dt>SPKI SHA-256</dt>
          <dd>
            <code>{status.ca.spkiSha256 || "—"}</code>
          </dd>
        </div>
        <div>
          <dt>Subject</dt>
          <dd>{status.ca.subject || "—"}</dd>
        </div>
        <div>
          <dt>Not after</dt>
          <dd>{status.ca.notAfter || "—"}</dd>
        </div>
      </dl>
      <p>
        <a href={CA_DOWNLOAD_URL} download="labmitm-ca.pem">
          Download lab CA certificate
        </a>{" "}
        <span className="muted">(PEM cert only; the private key is never exported)</span>
      </p>
      <h2>Store</h2>
      <dl>
        <div>
          <dt>Flows</dt>
          <dd>{status.store.flowCount}</dd>
        </div>
        <div>
          <dt>Bytes</dt>
          <dd>{formatBytes(status.store.storeBytes)}</dd>
        </div>
        <div>
          <dt>Generation</dt>
          <dd>{status.store.storeGeneration}</dd>
        </div>
        <div>
          <dt>Epoch</dt>
          <dd>{status.store.epoch}</dd>
        </div>
      </dl>
      <h2>Listeners</h2>
      <ul>
        {status.listeners.map((l) => (
          <li key={l.name}>
            {l.name}: <code>{l.address}</code>
          </li>
        ))}
      </ul>
      <h2>Features</h2>
      {featureError !== "" ? (
        <p className="banner-error" role="alert">
          {featureError}
        </p>
      ) : null}
      {features === null && featureError === "" ? <p role="status">Loading features…</p> : null}
      {features !== null ? (
        <>
          {canAdmin ? (
            <div className="field">
              <label htmlFor="feature-reason">Reason (optional)</label>
              <input
                id="feature-reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </div>
          ) : null}
          <table className="data">
            <thead>
              <tr>
                <th>ID</th>
                <th>Enabled</th>
                <th>Apply</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {features.items.map((f) => (
                <tr key={f.id}>
                  <td>
                    <code>{f.id}</code>
                  </td>
                  <td>
                    <span className="badge">{f.enabled ? "on" : "off"}</span>
                    {featureToggleable(f, canAdmin) ? (
                      <input
                        type="checkbox"
                        role="switch"
                        checked={f.enabled}
                        disabled={busy}
                        aria-label={`Toggle ${f.id}`}
                        onChange={() => void onToggle(f)}
                      />
                    ) : null}
                  </td>
                  <td>
                    <span>{f.applyMode}</span>
                    {f.applyMode === "reset" ? (
                      <>
                        {" "}
                        <Link to="/reset">Reset required</Link>
                      </>
                    ) : null}
                  </td>
                  <td>
                    {f.description}
                    {f.id === FEATURE_UI_ENABLED ? (
                      <div className="muted">
                        change via REST/MCP <code>setFeature</code> or bootstrap YAML
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
      <h2>Revisions</h2>
      <pre className="raw">{JSON.stringify(status.revisions, null, 2)}</pre>
    </main>
  );
}
