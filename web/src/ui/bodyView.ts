import type { Header } from "../api/types";

export const HEX_PREVIEW_BYTES = 4096;

export function headerValue(headers: readonly Header[] | undefined, name: string): string {
  if (!headers) {
    return "";
  }
  for (const h of headers) {
    if (h.name.toLowerCase() === name.toLowerCase()) {
      return h.value;
    }
  }
  return "";
}

export function contentTypeOf(headers: readonly Header[] | undefined): string {
  return headerValue(headers, "Content-Type");
}

export function isTextualContentType(ct: string): boolean {
  const base = ct.split(";")[0]?.trim().toLowerCase() ?? "";
  if (base.startsWith("text/")) {
    return true;
  }
  return (
    base === "application/json" ||
    base.endsWith("+json") ||
    base === "application/xml" ||
    base.endsWith("+xml") ||
    base === "application/javascript" ||
    base === "application/x-www-form-urlencoded" ||
    base === "application/problem+json"
  );
}

// Treat mostly-printable UTF-8/ASCII as text even when Content-Type is missing.
export function looksLikeText(body: string): boolean {
  if (body === "") {
    return true;
  }
  let bad = 0;
  const n = Math.min(body.length, HEX_PREVIEW_BYTES);
  for (let i = 0; i < n; i += 1) {
    const c = body.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13) {
      continue;
    }
    if (c < 32 || c === 127) {
      bad += 1;
    }
  }
  return bad / n < 0.1;
}

export function shouldRenderAsText(ct: string, body: string): boolean {
  if (ct !== "" && isTextualContentType(ct)) {
    return looksLikeText(body);
  }
  if (ct === "") {
    return looksLikeText(body);
  }
  return false;
}

export function toHexDump(body: string, maxBytes = HEX_PREVIEW_BYTES): string {
  const n = Math.min(body.length, maxBytes);
  const lines: string[] = [];
  for (let i = 0; i < n; i += 16) {
    const slice = body.slice(i, Math.min(i + 16, n));
    const hex = Array.from(slice, (ch) => ch.charCodeAt(0).toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice, (ch) => {
      const c = ch.charCodeAt(0);
      return c >= 32 && c < 127 ? ch : ".";
    }).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(47, " ")}  ${ascii}`);
  }
  if (body.length > maxBytes) {
    lines.push(`… truncated hex preview (${body.length} bytes total)`);
  }
  return lines.join("\n");
}
