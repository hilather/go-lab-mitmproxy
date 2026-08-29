import type { Flow } from "../api/types";

const SOCKS_CONNECT = "connect";

export function isTunnelNotDecrypt(flow: Flow): boolean {
  if (flow.intercepted) {
    return false;
  }
  if ((flow.error ?? "") !== "") {
    return false;
  }
  if (flow.state !== "completed" && flow.status !== 200) {
    return false;
  }
  if (flow.protocol === "connect") {
    return true;
  }
  if (flow.protocol === "socks5" || flow.protocol === "socks4") {
    return (flow.socks?.command ?? SOCKS_CONNECT) === SOCKS_CONNECT;
  }
  return false;
}

export function flowAuthority(flow: Flow): string {
  if (isTunnelNotDecrypt(flow)) {
    const socksDest = flow.socks?.dest ?? "";
    if (socksDest !== "") {
      return socksDest;
    }
    if ((flow.originalDest ?? "") !== "") {
      return flow.originalDest ?? "";
    }
  }
  return flow.host || flow.url;
}

function authorityPortSuffix(authority: string): string {
  if (authority === "") {
    return "";
  }
  if (authority.startsWith("[")) {
    const end = authority.lastIndexOf("]");
    if (end >= 0 && authority.slice(end + 1, end + 2) === ":") {
      return authority.slice(end + 2);
    }
    return "";
  }
  const i = authority.lastIndexOf(":");
  if (i <= 0 || i === authority.length - 1) {
    return "";
  }
  if (authority.includes(":") && authority.indexOf(":") !== i) {
    return "";
  }
  return authority.slice(i + 1);
}

export function isLDAPSAuthority(flow: Flow): boolean {
  for (const raw of [flow.socks?.dest ?? "", flow.originalDest ?? ""]) {
    const port = authorityPortSuffix(raw);
    if (port === "3636" || port === "636") {
      return true;
    }
  }
  return false;
}

export function tunnelSubtitle(flow: Flow): string {
  if (isLDAPSAuthority(flow)) {
    return "CONNECT · LDAPS";
  }
  return "CONNECT · tunnel";
}

export function methodLabel(flow: Flow): string {
  if (isTunnelNotDecrypt(flow) || flow.method.toUpperCase() === "CONNECT") {
    return "CONN";
  }
  return flow.method || "?";
}

export function methodTone(flow: Flow): "tunnel" | "http" {
  if (isTunnelNotDecrypt(flow) || flow.method.toUpperCase() === "CONNECT") {
    return "tunnel";
  }
  return "http";
}

export function listStatusLabel(flow: Flow): string {
  if (isTunnelNotDecrypt(flow)) {
    return "tunnel";
  }
  if (flow.status > 0) {
    return String(flow.status);
  }
  return flow.state || "—";
}

export function listTimingLabel(flow: Flow): string {
  if (isTunnelNotDecrypt(flow) && flow.timings.totalMs === 0) {
    return "-";
  }
  if (flow.timings.totalMs > 0) {
    return `${flow.timings.totalMs}ms`;
  }
  return "-";
}

export function flowPath(flow: Flow): string {
  if (isTunnelNotDecrypt(flow)) {
    return tunnelSubtitle(flow);
  }
  const raw = flow.url || "";
  if (raw === "") {
    return "/";
  }
  try {
    const u = new URL(raw);
    return `${u.pathname}${u.search}`;
  } catch {
    const i = raw.indexOf("/", raw.indexOf("//") >= 0 ? raw.indexOf("//") + 2 : 0);
    return i >= 0 ? raw.slice(i) : raw;
  }
}

export function matchesFlowSearch(flow: Flow, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (needle === "") {
    return true;
  }
  const hay = [
    flow.host,
    flow.url,
    flow.method,
    methodLabel(flow),
    String(flow.status),
    flow.state,
    flow.protocol,
    listStatusLabel(flow),
    isTunnelNotDecrypt(flow) ? tunnelSubtitle(flow) : "",
    flow.socks?.dest ?? "",
    flow.originalDest ?? "",
  ]
    .join(" ")
    .toLowerCase();
  return hay.includes(needle);
}

export const TUNNEL_REASON = "why not decrypted: port not in tls.ports:[443]";
export const FLOWS_FOOTER =
  "CONNECT to LDAPS/TacLab TLS is tunnel-not-decrypt. Intercept is :443 only.";
