import { describe, expect, it } from "vitest";
import type { Flow } from "../api/types";
import {
  isLDAPSAuthority,
  isTunnelNotDecrypt,
  listStatusLabel,
  matchesFlowSearch,
  methodLabel,
  tunnelSubtitle,
} from "./flowKind";

function base(over: Partial<Flow> = {}): Flow {
  return {
    id: "01J",
    state: "completed",
    method: "GET",
    url: "https://app.lab/login",
    host: "app.lab",
    scheme: "https",
    protocol: "http/1.1",
    status: 200,
    intercepted: true,
    truncated: false,
    requestBytes: 0,
    responseBytes: 12,
    timings: { dnsMs: 0, connectMs: 1, tlsMs: 2, ttfbMs: 3, totalMs: 4 },
    request: { size: 0, truncated: false },
    response: { size: 12, truncated: false },
    ...over,
  };
}

describe("isTunnelNotDecrypt", () => {
  it("is true for a completed raw CONNECT", () => {
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          error: "",
          status: 200,
          url: "",
          host: "directory",
        }),
      ),
    ).toBe(true);
  });

  it("is false for tls_handshake / http2_inner / DNS", () => {
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          state: "error",
          status: 0,
          error: "tls_handshake",
        }),
      ),
    ).toBe(false);
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          state: "error",
          status: 0,
          error: "http2_inner",
        }),
      ),
    ).toBe(false);
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          state: "error",
          status: 502,
          error: "dns",
        }),
      ),
    ).toBe(false);
  });

  it("is false for intercepted inner HTTP", () => {
    expect(isTunnelNotDecrypt(base())).toBe(false);
  });

  it("is false for SOCKS BIND and UDP", () => {
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "socks5",
          intercepted: false,
          status: 0,
          socks: { command: "bind", dest: "192.0.2.10:443" },
        }),
      ),
    ).toBe(false);
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "socks5",
          intercepted: false,
          status: 0,
          socks: { command: "udp", dest: "192.0.2.10:53" },
        }),
      ),
    ).toBe(false);
  });

  it("is true for SOCKS CONNECT", () => {
    expect(
      isTunnelNotDecrypt(
        base({
          method: "CONNECT",
          protocol: "socks5",
          intercepted: false,
          status: 0,
          socks: { command: "connect", dest: "app.lab:443" },
        }),
      ),
    ).toBe(true);
  });
});

describe("LDAPS subtitle", () => {
  it("is true only from socks.dest or originalDest port 3636/636", () => {
    expect(
      isLDAPSAuthority(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          host: "directory",
          socks: { dest: "directory:3636" },
        }),
      ),
    ).toBe(true);
    expect(
      isLDAPSAuthority(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          host: "192.0.2.10",
          originalDest: "192.0.2.10:3636",
        }),
      ),
    ).toBe(true);
    expect(
      isLDAPSAuthority(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          host: "directory",
        }),
      ),
    ).toBe(false);
    expect(
      isLDAPSAuthority(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          host: "directory:3636",
        }),
      ),
    ).toBe(false);
    expect(tunnelSubtitle(base({ host: "directory", intercepted: false, protocol: "connect" }))).toBe(
      "CONNECT · tunnel",
    );
  });
});

describe("list labels", () => {
  it("shows CONN and tunnel for raw CONNECT", () => {
    const f = base({
      method: "CONNECT",
      protocol: "connect",
      intercepted: false,
      status: 200,
    });
    expect(methodLabel(f)).toBe("CONN");
    expect(listStatusLabel(f)).toBe("tunnel");
  });

  it("keeps state when status is 0 and not a tunnel", () => {
    expect(
      listStatusLabel(
        base({
          method: "CONNECT",
          protocol: "connect",
          intercepted: false,
          status: 0,
          state: "error",
          error: "tls_handshake",
        }),
      ),
    ).toBe("error");
  });

  it("matches CONN and tunnel in search", () => {
    const f = base({
      method: "CONNECT",
      protocol: "connect",
      intercepted: false,
      status: 200,
    });
    expect(matchesFlowSearch(f, "CONN")).toBe(true);
    expect(matchesFlowSearch(f, "tunnel")).toBe(true);
    expect(matchesFlowSearch(f, "maildev")).toBe(false);
  });
});
