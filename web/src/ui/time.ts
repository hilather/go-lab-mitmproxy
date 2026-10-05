// Local-time rendering for server RFC3339 timestamps. The ISO value stays
// available to callers (title/dateTime) so nothing is lost.

function parse(iso: string): Date | null {
  if (iso === "") return null;
  // Go emits nanosecond fractions; Date only parses milliseconds reliably.
  const trimmed = iso.replace(/(\.\d{3})\d+/, "$1");
  const d = new Date(trimmed);
  return Number.isNaN(d.getTime()) ? null : d;
}

function pad(n: number, width = 2): string {
  return String(n).padStart(width, "0");
}

/** localTime renders HH:MM:SS in the browser's zone; invalid input is returned unchanged. */
export function localTime(iso: string | undefined): string {
  const d = parse(iso ?? "");
  if (d === null) return iso ?? "";
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/** localDateTime renders YYYY-MM-DD HH:MM:SS.mmm in the browser's zone. */
export function localDateTime(iso: string | undefined): string {
  const d = parse(iso ?? "");
  if (d === null) return iso ?? "";
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${localTime(iso)}.${pad(d.getMilliseconds(), 3)}`;
}

/** zoneLabel is a short name for the browser's zone, e.g. "EDT". */
export function zoneLabel(at: Date = new Date()): string {
  try {
    const part = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" })
      .formatToParts(at)
      .find((p) => p.type === "timeZoneName");
    return part?.value ?? "";
  } catch {
    return "";
  }
}
