import { FormEvent, useCallback, useEffect, useRef, useState } from "react";
import { errorMessage, getStatus, resetState } from "../api/client";
import { localTime } from "../ui/time";
import { useAuth } from "../auth/AuthProvider";
import { SCOPE_ADMIN } from "../auth/scopes";
import { RESET_PHRASE, canSubmitReset } from "../ui/forbidden";

export function ResetPage() {
  const { hasScope } = useAuth();
  const allowed = hasScope(SCOPE_ADMIN);
  const [phrase, setPhrase] = useState("");
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const ok = canSubmitReset(phrase, confirmed, allowed);
  // Impact line from the existing GET /v1/status, shown as a labelled snapshot (not live): read on mount,
  // when the confirm box is ticked, after a successful reset and on Refresh count. A failed read hides
  // the line without an alert.
  const [impact, setImpact] = useState<{ at: string; flows: number; generation: number } | null>(null);
  const impactGeneration = useRef(0);
  const readImpact = useCallback(async () => {
    const mine = ++impactGeneration.current;
    try {
      const status = await getStatus();
      if (mine === impactGeneration.current)
        setImpact({ at: new Date().toISOString(), flows: status.store.flowCount, generation: status.store.storeGeneration });
    } catch {
      if (mine === impactGeneration.current) setImpact(null);
    }
  }, []);
  useEffect(() => {
    void readImpact();
    return () => {
      impactGeneration.current++;
    };
  }, [readImpact]);

  async function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    if (!ok) {
      return;
    }
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await resetState(reason.trim());
      setNotice("Reset completed. Bootstrap was reread and the flow store was wiped.");
      setPhrase("");
      setConfirmed(false);
      void readImpact();
    } catch (err) {
      setError(errorMessage(err, "Reset failed."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page page--narrow">
      <p className="kicker">Reset</p>
      <h1>Reset</h1>
      <p>
        Reset rereads the mounted bootstrap YAML and wipes captured flows. Type{" "}
        <code>{RESET_PHRASE}</code> to enable the control.
      </p>
      {!allowed ? <p className="muted">Requires scope mitm.admin.</p> : null}
      {error !== "" ? (
        <p className="banner-error" role="alert">
          {error}
        </p>
      ) : null}
      {notice !== "" ? <p className="muted" role="status">{notice}</p> : null}
      <form className="stack panel" onSubmit={(e) => void onSubmit(e)}>
        <div className="field">
          <label htmlFor="reset-phrase">Confirmation phrase</label>
          <input
            id="reset-phrase"
            value={phrase}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setPhrase(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="reset-reason">Reason (optional)</label>
          <input id="reset-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
        </div>
        <label>
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => {
              setConfirmed(e.target.checked);
              if (e.target.checked) void readImpact();
            }}
          /> Wipe
          the flow store and reload bootstrap
        </label>
        {impact ? (
          <p className="note note-danger reset-impact" data-testid="reset-impact">
            <span>
              Snapshot at <time dateTime={impact.at} title={impact.at}>{localTime(impact.at)}</time>: {impact.flows}{" "}
              {impact.flows === 1 ? "flow" : "flows"} · store generation {impact.generation}.
            </span>
            <span>Not live: Reset wipes whatever the store holds when it runs.</span>
            <button type="button" className="btn-sm" onClick={() => void readImpact()}>
              Refresh count
            </button>
          </p>
        ) : null}
        <button type="submit" className="btn-danger-fill" disabled={!ok || busy}>
          {busy ? "Resetting…" : "Reset LabMITM"}
        </button>
      </form>
    </main>
  );
}
