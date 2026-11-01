import { useRef, useState } from "react";
import type { AuditReport, PipelineEvent } from "./types";
import { sampleAudit } from "./sampleAudit";
import { ReportView } from "./components/ReportView";
import { RunLog } from "./components/RunLog";

type View = "idle" | "running" | "done";

function Logo() {
  return (
    <svg className="logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="g" x1="0" y1="0" x2="48" y2="48">
          <stop stopColor="#38bdf8" />
          <stop offset="1" stopColor="#7c93ff" />
        </linearGradient>
      </defs>
      <path d="M24 3l17 7v11c0 10.5-7 19.6-17 24C14 40.6 7 31.5 7 21V10l17-7z" fill="url(#g)" opacity="0.18" />
      <path d="M24 3l17 7v11c0 10.5-7 19.6-17 24C14 40.6 7 31.5 7 21V10l17-7z" stroke="url(#g)" strokeWidth="2" strokeLinejoin="round" />
      <path d="M22 16l-6 9h6l-2 8 10-11h-6l2-6z" fill="url(#g)" />
    </svg>
  );
}

export function App() {
  const [view, setView] = useState<View>("idle");
  const [repo, setRepo] = useState("");
  const [contract, setContract] = useState("");
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [error, setError] = useState<string>();
  const [report, setReport] = useState<AuditReport>();
  const esRef = useRef<EventSource | null>(null);

  function start(e: React.FormEvent) {
    e.preventDefault();
    const url = repo.trim();
    if (!url) return;
    setEvents([]);
    setError(undefined);
    setReport(undefined);
    setView("running");

    const q = new URLSearchParams({ repo: url });
    if (contract.trim()) q.set("contract", contract.trim());
    const es = new EventSource(`/api/audit?${q.toString()}`);
    esRef.current = es;

    es.onmessage = (msg) => {
      let ev: PipelineEvent;
      try {
        ev = JSON.parse(msg.data);
      } catch {
        return;
      }
      if (ev.stage === "done" && ev.report) {
        setReport(ev.report);
        setView("done");
        es.close();
        return;
      }
      if (ev.stage === "error") {
        setError(ev.message);
        es.close();
        return;
      }
      setEvents((prev) => [...prev, ev]);
    };
    es.onerror = () => {
      setError((prev) => prev ?? "connection to the audit server was lost (is sentinelx-server running?)");
      es.close();
    };
  }

  function reset() {
    esRef.current?.close();
    setView("idle");
    setReport(undefined);
    setEvents([]);
    setError(undefined);
  }

  return (
    <div className="wrap">
      <header className="hero">
        <Logo />
        <div>
          <h1>SentinelX</h1>
          <div className="tag">
            Proof-carrying smart-contract auditing — <b>every finding is a running exploit</b>, not a guess.
          </div>
        </div>
      </header>

      {view === "idle" && (
        <>
          <form className="repoform" onSubmit={start}>
            <label className="field">
              <span>GitHub repository</span>
              <input
                type="text"
                placeholder="https://github.com/owner/foundry-project"
                value={repo}
                onChange={(e) => setRepo(e.target.value)}
                autoFocus
              />
            </label>
            <label className="field narrow">
              <span>Contract (optional)</span>
              <input type="text" placeholder="auto-detect" value={contract} onChange={(e) => setContract(e.target.value)} />
            </label>
            <button className="btn" type="submit">
              Audit repository
            </button>
          </form>
          <p className="hint">
            Point it at a Foundry project. It compiles the repo, hypothesizes vulnerabilities, writes and runs real exploits, and
            reports only the ones it can prove. Or{" "}
            <button className="linklike" onClick={() => { setReport(sampleAudit); setView("done"); }}>
              view a sample report
            </button>
            .
          </p>
        </>
      )}

      {view === "running" && <RunLog events={events} error={error} />}
      {view === "running" && error && (
        <div style={{ marginTop: 16 }}>
          <button className="btn ghost" onClick={reset}>
            Back
          </button>
        </div>
      )}

      {view === "done" && report && <ReportView report={report} onReset={reset} />}

      <div className="footer">
        A finding is marked verified only when the exploit compiled, ran in Foundry, used no test-environment cheats, and broke a
        guarded invariant. Proves presence, not absence — recall is bounded by the hypothesis stage.
      </div>
    </div>
  );
}
