import type { PipelineEvent } from "../types";

const STAGE_LABEL: Record<string, string> = {
  ingest: "Ingest",
  note: "Note",
  hypothesize: "Hypothesize",
  prove: "Exploit",
  verdict: "Verify",
  report: "Report",
  error: "Error",
};

export function RunLog({ events, error }: { events: PipelineEvent[]; error?: string }) {
  return (
    <div className="runlog">
      <div className="runlog-head">
        <span className="spinner" aria-hidden />
        <span>Auditing…</span>
      </div>
      <div className="runlog-body">
        {events.map((e, i) => (
          <div className={`logline ${e.stage}`} key={i}>
            <span className="logstage">{STAGE_LABEL[e.stage] ?? e.stage}</span>
            <span className="logmsg">
              {e.message}
              {e.verdict && <span className={`verdict-badge ${e.verdict}`} style={{ marginLeft: 8 }}>{e.verdict}</span>}
            </span>
          </div>
        ))}
        {error && (
          <div className="logline error">
            <span className="logstage">Error</span>
            <span className="logmsg">{error}</span>
          </div>
        )}
      </div>
    </div>
  );
}
