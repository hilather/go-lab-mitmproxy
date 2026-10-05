import { describe, expect, it } from "vitest";
import type { Flow } from "../api/types";
import {
  isLDAPSAuthority,
  isTunnelNotDecrypt,
  listStatusLabel,
  listStatusText,
  matchesFlowSearch,
  methodLabel,
  statusBucket,
  statusTone,
  tunnelSubtitle,
  type StatusTone,
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

describe("status tone and buckets", () => {
  const cases: [Partial<Flow>, StatusTone, string | null, string][] = [
    [{ status: 200 }, "ok", "2xx", "200"],
    [{ status: 200, state: "dropped" }, "danger", "5xx", "200"],
    [{ status: 0, state: "dropped" }, "danger", "5xx", "dropped"],
    [{ status: 0, state: "completed", error: "breakpoint_timeout" }, "danger", "5xx", "bp timeout"],
    [{ status: 302 }, "ok", null, "302"],
    [{ status: 403 }, "warn", "4xx", "403"],
    [{ status: 404 }, "warn", "4xx", "404"],
    [{ status: 502 }, "danger", "5xx", "502"],
    [{ status: 0, state: "error", error: "breakpoint_timeout" }, "danger", "5xx", "bp timeout"],
    [{ status: 0, state: "paused", pausedPhase: "request" }, "paused", "paused", "paused"],
    [{ status: 0, state: "open" }, "muted", null, "open"],
  ];
  for (const [patch, tone, bucket, text] of cases) {
    it(`classifies ${JSON.stringify(patch)}`, () => {
      const flow = base({ intercepted: true, ...patch });
      expect(statusTone(flow)).toBe(tone);
      expect(statusBucket(flow)).toBe(bucket);
      expect(listStatusText(flow)).toBe(text);
    });
  }
  it("keeps tunnels out of the 2xx bucket (All only) with the tunnel tone", () => {
    const flow = base({ intercepted: false, error: "", state: "completed", status: 200, protocol: "connect", method: "CONNECT" });
    expect(statusTone(flow)).toBe("tunnel");
    expect(statusBucket(flow)).toBeNull();
  });
});
