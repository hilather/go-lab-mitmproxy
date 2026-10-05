import { createRoot } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { LiveSpecProvider } from "../src/api/liveSpec";
import { FlowFilters } from "../src/pages/FlowFilters";
import "../src/styles.css";

const session = {
  id: "admin",
  role: "administrator",
  scopes: ["mitm.read", "mitm.write", "mitm.admin", "mitm.audit.read"],
  csrf: "csrf-harness",
  expiresAt: "2099-01-01T00:00:00Z",
};

const state = {
  canonical: { revision: "r1", spec: { rules: { items: [] } } },
  runtime: { revision: "r1" },
};

window.fetch = async (input: RequestInfo | URL) => {
  const url = String(input);
  if (url.includes("/v1/session")) {
    return new Response(JSON.stringify(session), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  if (url.includes("/v1/state")) {
    return new Response(JSON.stringify(state), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ title: "not found", status: 404 }), {
    status: 404,
    headers: { "Content-Type": "application/problem+json" },
  });
};

createRoot(document.getElementById("root")!).render(
  <MemoryRouter>
    <LiveSpecProvider>
      <header data-testid="outside-topbar" className="topbar" style={{ padding: "0.5rem" }}>
        LabMITM harness
      </header>
      <p className="kicker" data-testid="outside-kicker">
        Captured <span className="mono">0</span>
      </p>
      <h1 data-testid="outside-h1">GET https://shop.lab/very/long/path</h1>
      <label>
        Host, method, or status
        <input id="flow-search" name="q" placeholder="Host, method, or status" />
      </label>
      <FlowFilters onFilter={() => {}} />
      <footer data-testid="outside-footer">footer chrome</footer>
    </LiveSpecProvider>
  </MemoryRouter>,
);
