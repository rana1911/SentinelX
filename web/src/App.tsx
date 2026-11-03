import { useRef, useState } from "react";
import type { AuditReport, PipelineEvent } from "./types";
import { sampleAudit } from "./sampleAudit";
import { ReportView } from "./components/ReportView";
import { RunLog } from "./components/RunLog";

type View = "idle" | "running" | "done";

const BRAND = "SentinelX";

// One-click demo targets — EDIT these URLs to your own vulnerable repos.
const DEMOS = [
  { label: "UnsafeBank", sub: "access control", repo: "https://github.com/rana1911/demo2" },
  { label: "ReentrantVault", sub: "reentrancy", repo: "https://github.com/rana1911/demo1" },
];

const PIPELINE = [
  { t: "Ingest", s: "clone + forge build, read the ABI" },
  { t: "Hypothesize", s: "the model proposes concrete bugs" },
  { t: "Exploit", s: "it writes & runs a real PoC" },
  { t: "Verify", s: "trace-level proof, no cheats" },
  { t: "Report", s: "only what was actually proven" },
];

const FEATURES = [
  {
    icon: "⚡",
    title: "Running exploits, not guesses",
    body: "A finding counts only if its exploit compiled, executed in Foundry, and broke a guarded invariant. No hallucinated vulnerabilities.",
  },
  {
    icon: "🛡️",
    title: "Cheat-resistant verification",
    body: "Deterministic trace analysis rejects test-tool shortcuts — even an obfuscated cheat that passes a source scan and forge is caught.",
  },
  {
    icon: "🧩",
    title: "Class-independent",
    body: "Proves any bug that breaks an on-chain invariant — not just patterns it was hand-coded to recognize. Reentrancy, access control, and beyond.",
  },
  {
    icon: "🔁",
    title: "Reproducible proof",
    body: "Every verified finding ships with the exact attacker code and the trace evidence — drop it into Foundry and watch it drain.",
  },
];

function Logo({ size = 46 }: { size?: number }) {
  return (
    <svg className="logo" width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
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

  function startWith(url: string, contractName = "") {
    if (!url.trim()) return;
    setEvents([]);
    setError(undefined);
    setReport(undefined);
    setView("running");

    const q = new URLSearchParams({ repo: url.trim() });
    if (contractName.trim()) q.set("contract", contractName.trim());
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
      setError((prev) => prev ?? "connection to the audit server was lost (is the server running?)");
      es.close();
    };
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    startWith(repo, contract);
  }

  function reset() {
    esRef.current?.close();
    setView("idle");
    setReport(undefined);
    setEvents([]);
    setError(undefined);
  }

  return (
    <div className={`wrap ${view === "idle" ? "landing" : ""}`}>
      <header className="hero">
        <Logo />
        <div>
          <h1>{BRAND}</h1>
          <div className="tag">
            Proof-carrying smart-contract auditing — <b>every finding is a running exploit</b>, not a guess.
          </div>
        </div>
      </header>

      {view === "idle" && (
        <>
          <section className="pitch">
            <h2>
              An LLM finds the bug. A real exploit <span className="accentgrad">proves</span> it.
            </h2>
            <p>
              Point {BRAND} at any Foundry repo. It hypothesizes vulnerabilities, writes exploits, and runs them against real{" "}
              <code>forge</code> — reporting only the ones it can actually demonstrate, each with a reproducible proof-of-concept.
            </p>
          </section>

          <form className="repoform" onSubmit={submit}>
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

          <div className="demos">
            <span className="demos-label">Try a live demo</span>
            {DEMOS.map((d) => (
              <button key={d.repo} className="demo-chip" onClick={() => startWith(d.repo)}>
                <span className="dc-name">{d.label}</span>
                <span className="dc-sub">{d.sub}</span>
              </button>
            ))}
            <button className="linklike" onClick={() => { setReport(sampleAudit); setView("done"); }}>
              or view a sample report →
            </button>
          </div>

          <div className="how">
            <div className="section-eyebrow">How it works</div>
            <div className="howrow">
              {PIPELINE.map((p, i) => (
                <div className="howstep" key={p.t}>
                  <div className="hs-num">{i + 1}</div>
                  <div className="hs-title">{p.t}</div>
                  <div className="hs-sub">{p.s}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="features">
            {FEATURES.map((f) => (
              <div className="feature" key={f.title}>
                <div className="f-icon">{f.icon}</div>
                <div className="f-title">{f.title}</div>
                <div className="f-body">{f.body}</div>
              </div>
            ))}
          </div>
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
