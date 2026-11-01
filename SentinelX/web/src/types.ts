// Mirrors internal/report/json.go (the `exploitforge -report-json` output).
export type Verdict = "verified" | "rejected" | "inconclusive";

export interface Summary {
  total: number;
  verified: number;
  rejected: number;
  inconclusive: number;
}

export interface Finding {
  id: string;
  class: string;
  contract: string;
  function: string;
  verdict: Verdict;
  reason: string;
  confidence: number;
  impact?: string;
  successAssertion?: string;
  claimsProfit: boolean;
  attackSteps?: string[];
  evidenceNotes?: string[];
  valueFlowWei: number;
  reentrancyConfirmed: boolean;
  attempts: number;
  poc?: string;
}

export interface AuditReport {
  target: string;
  provider?: string;
  model?: string;
  summary: Summary;
  findings: Finding[];
}

// Server-Sent Event from exploitforge-server (mirrors internal/pipeline.Event).
export interface PipelineEvent {
  stage: "ingest" | "note" | "hypothesize" | "prove" | "verdict" | "report" | "done" | "error";
  message: string;
  hypothesisId?: string;
  verdict?: Verdict;
  report?: AuditReport;
}
