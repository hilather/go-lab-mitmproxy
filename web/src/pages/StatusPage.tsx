import { useEffect, useState } from "react";
import { APIError, CA_DOWNLOAD_URL, getStatus } from "../api/client";
import type { Status } from "../api/types";
import { formatBytes } from "../auth/scopes";

export function StatusPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        setStatus(await getStatus());
      } catch (err) {
        setError(err instanceof APIError ? err.message : "Could not load status.");
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
      <h2>Revisions</h2>
      <pre className="raw">{JSON.stringify(status.revisions, null, 2)}</pre>
    </main>
  );
}
