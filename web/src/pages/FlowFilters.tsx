import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { waitFlow } from "../api/client";
import type { FlowListQuery, WaitFilter } from "../api/types";

const shared = [
  "host",
  "method",
  "status",
  "pathPrefix",
  "protocol",
  "via",
] as const;

export function FlowFilters({
  onFilter,
}: {
  onFilter: (query: FlowListQuery) => void;
}) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [timeout, setTimeout] = useState("30s");
  const [waiting, setWaiting] = useState(false);
  const [message, setMessage] = useState("");
  const controller = useRef<AbortController | null>(null);
  const navigate = useNavigate();
  useEffect(() => () => controller.current?.abort(), []);

  async function wait() {
    if (
      values.status &&
      (!/^\d+$/.test(values.status) ||
        !Number.isSafeInteger(Number(values.status)))
    ) {
      setMessage("Status must be a non-negative integer.");
      return;
    }
    const current = new AbortController();
    controller.current = current;
    setWaiting(true);
    setMessage("");
    const filter: WaitFilter = {};
    for (const key of shared) {
      if (values[key]) {
        Object.assign(filter, {
          [key]: key === "status" ? Number(values[key]) : values[key],
        });
      }
    }
    if (values.intercepted) filter.intercepted = values.intercepted === "true";
    if (values.after) filter.after = values.after;
    try {
      const flow = await waitFlow(filter, timeout, current.signal);
      if (!current.signal.aborted) {
        setMessage(`Matched flow ${flow.id}`);
        navigate(`/flows/${encodeURIComponent(flow.id)}`);
      }
    } catch (err) {
      if (!current.signal.aborted) {
        setMessage(err instanceof Error ? err.message : "Wait failed.");
      }
    } finally {
      if (controller.current === current) {
        controller.current = null;
        setWaiting(false);
      }
    }
  }

  function applyFilters() {
    const query: FlowListQuery = {};
    for (const key of [...shared, "scheme", "ruleId", "intercepted"] as const) {
      if (values[key]) query[key] = values[key];
    }
    onFilter(query);
  }

  return (
    <details>
      <summary>Server filters and wait</summary>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          applyFilters();
        }}
      >
        {[...shared, "scheme", "ruleId"].map((key) => (
          <label key={key}>
            {key}
            <input
              value={values[key] || ""}
              onChange={(event) =>
                setValues({ ...values, [key]: event.target.value })
              }
            />
          </label>
        ))}
        <label>
          Intercepted filter
          <select
            value={values.intercepted || ""}
            onChange={(event) =>
              setValues({ ...values, intercepted: event.target.value })
            }
          >
            <option value="">Any</option>
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        </label>
        <button type="submit">Apply server filters</button>
        <label>
          Wait after (RFC3339)
          <input
            value={values.after || ""}
            onChange={(event) =>
              setValues({ ...values, after: event.target.value })
            }
          />
        </label>
        <label>
          Wait timeout (Go duration)
          <input
            value={timeout}
            onChange={(event) => setTimeout(event.target.value)}
          />
        </label>
        <p>
          Wait uses host, method, status, pathPrefix, protocol, via, intercepted
          and after. Scheme and ruleId apply to the list only.
        </p>
        <button type="button" disabled={waiting} onClick={() => void wait()}>
          Wait for flow
        </button>
        {waiting ? (
          <button
            type="button"
            onClick={() => {
              controller.current?.abort();
              setWaiting(false);
              setMessage("Wait cancelled.");
            }}
          >
            Cancel wait
          </button>
        ) : null}
        {message ? <p role="status">{message}</p> : null}
      </form>
    </details>
  );
}
