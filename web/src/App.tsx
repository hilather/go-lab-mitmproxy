import { type ReactNode } from "react";
import { BrowserRouter, NavLink, Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { InterceptChip, LiveSpecProvider } from "./api/liveSpec";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { SCOPE_ADMIN, SCOPE_AUDIT } from "./auth/scopes";
import { AuditPage } from "./pages/AuditPage";
import { FlowsWorkspace } from "./pages/FlowsWorkspace";
import { LoginPage } from "./pages/LoginPage";
import { ResetPage } from "./pages/ResetPage";
import { StatusPage } from "./pages/StatusPage";
import { navItems } from "./ui/forbidden";

function SkipLink() {
  return (
    <a className="skip-link" href="#app-main">
      Skip to main content
    </a>
  );
}

function flowsNavActive(pathname: string): boolean {
  return pathname === "/" || pathname.startsWith("/flows/");
}

function NavItem({ to, children }: { to: string; children: ReactNode }) {
  const { pathname } = useLocation();
  return (
    <NavLink
      to={to}
      className={({ isActive }) => {
        const active = to === "/" ? flowsNavActive(pathname) : isActive;
        return active ? "nav-active" : undefined;
      }}
      end={to === "/"}
    >
      {children}
    </NavLink>
  );
}

function SignedInChrome({
  items,
  logout,
}: {
  items: { to: string; label: string }[];
  logout: () => void | Promise<void>;
}) {
  return (
    <>
      <header className="topbar">
        <NavLink className="brand" to="/">
          <span className="status-dot" aria-hidden="true" />
          LabMITM
        </NavLink>
        <div className="topbar-chips">
          <span className="chip chip-accent">live</span>
          <InterceptChip />
          <button type="button" className="linkish" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>
      <nav className="sidenav" aria-label="Primary">
        {items.map((item) => (
          <NavItem key={item.to} to={item.to}>
            {item.label}
          </NavItem>
        ))}
      </nav>
      <div id="app-main">
        <Outlet />
      </div>
    </>
  );
}

export function Shell() {
  const { state, hasScope, logout } = useAuth();
  const signedIn = state.status === "signed_in";
  const items = signedIn ? navItems(hasScope(SCOPE_AUDIT), hasScope(SCOPE_ADMIN)) : [];
  return (
    <div className="app">
      <SkipLink />
      {signedIn ? (
        <LiveSpecProvider>
          <SignedInChrome items={items} logout={logout} />
        </LiveSpecProvider>
      ) : (
        <>
          <header className="topbar">
            <NavLink className="brand" to="/">
              <span className="status-dot" aria-hidden="true" />
              LabMITM
            </NavLink>
          </header>
          <div id="app-main">
            <Outlet />
          </div>
        </>
      )}
    </div>
  );
}

function RequireSession() {
  const { state } = useAuth();
  if (state.status === "loading") {
    return (
      <main className="page">
        <p className="muted" role="status">
          Checking session…
        </p>
      </main>
    );
  }
  if (state.status !== "signed_in") {
    return <Navigate to="/login" replace />;
  }
  return <Outlet />;
}

function RedirectIfSignedIn() {
  const { state } = useAuth();
  if (state.status === "loading") {
    return (
      <main className="page">
        <p className="muted" role="status">
          Checking session…
        </p>
      </main>
    );
  }
  if (state.status === "signed_in") {
    return <Navigate to="/" replace />;
  }
  return <Outlet />;
}

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Shell />}>
        <Route element={<RedirectIfSignedIn />}>
          <Route path="/login" element={<LoginPage />} />
        </Route>
        <Route element={<RequireSession />}>
          <Route element={<FlowsWorkspace />}>
            <Route path="/" element={<></>} />
            <Route path="/flows/:id" element={<></>} />
          </Route>
          <Route path="/status" element={<StatusPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/reset" element={<ResetPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}

