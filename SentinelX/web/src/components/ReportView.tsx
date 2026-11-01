import type { AuditReport } from "../types";
import { FindingCard } from "./FindingCard";

const PIPELINE = [
  { t: "Ingest", s: "forge build + ABI" },
  { t: "Hypothesize", s: "LLM finds leads" },
  { t: "Exploit", s: "write + run PoC" },
  { t: "Verify", s: "trace-based proof" },
  { t: "Report", s: "verified findings" },
];

export function ReportView({ report, onReset }: { report: AuditReport; onReset?: () => void }) {
  const { summary, findings } = report;
  const verified = findings.filter((f) => f.verdict === "verified");
  const others = findings.filter((f) => f.verdict !== "verified");

  return (
    <>
      <div className="target-bar">
        <span className="contract">{report.target}</span>
        {report.model && <span className="chip">model: {report.model}</span>}
        <span className="chip">{summary.total} hypotheses tested</span>
        <span className="spacer" />
        {onReset && (
          <button className="btn ghost" onClick={onReset}>
            New audit
          </button>
        )}
      </div>

      <div className="stats">
        <div className="stat v">
          <div className="n">{summary.verified}</div>
          <div className="l">Verified</div>
        </div>
        <div className="stat r">
          <div className="n">{summary.rejected}</div>
          <div className="l">Rejected</div>
        </div>
        <div className="stat i">
          <div className="n">{summary.inconclusive}</div>
          <div className="l">Inconclusive</div>
        </div>
        <div className="stat">
          <div className="n">{summary.total}</div>
          <div className="l">Total</div>
        </div>
      </div>

      <div className="pipeline">
        {PIPELINE.map((p, i) => (
          <div key={p.t} style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div className="pstep">
              <span className="dot">{i + 1}</span>
              <div>
                <div className="pt">{p.t}</div>
                <div className="ps">{p.s}</div>
              </div>
            </div>
            {i < PIPELINE.length - 1 && (
              <svg className="parrow" width="20" height="12" viewBox="0 0 20 12" fill="none">
                <path d="M1 6h17m0 0l-5-4m5 4l-5 4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
          </div>
        ))}
      </div>

      <div className="sec-title">Verified vulnerabilities</div>
      {verified.length === 0 ? (
        <div className="finding">
          <div className="fbody" style={{ borderTop: "none", paddingTop: 18 }}>
            <p className="reason">No hypothesis produced an exploit that survived verification.</p>
          </div>
        </div>
      ) : (
        verified.map((f) => <FindingCard key={f.id} f={f} defaultOpen />)
      )}

      {others.length > 0 && (
        <>
          <div className="sec-title">Not confirmed</div>
          {others.map((f) => (
            <FindingCard key={f.id} f={f} />
          ))}
        </>
      )}
    </>
  );
}
