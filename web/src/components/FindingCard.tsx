import { useState } from "react";
import type { Finding } from "../types";
import { Code } from "./Code";

function formatEth(wei: number): string {
  if (!wei) return "0";
  const eth = wei / 1e18;
  if (eth >= 0.001) return `${eth % 1 === 0 ? eth : eth.toFixed(3)} ETH`;
  return `${wei} wei`;
}

export function FindingCard({ f, defaultOpen }: { f: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(!!defaultOpen);
  const verified = f.verdict === "verified";

  return (
    <div className={`finding ${verified ? "v" : ""}`}>
      <div className="fhead" onClick={() => setOpen((o) => !o)}>
        <span className={`verdict-badge ${f.verdict}`}>{f.verdict}</span>
        <div className="ftitle">
          <div className="main">
            <code>
              {f.contract}.{f.function}
            </code>
          </div>
          <div className="sub">{f.impact || f.reason}</div>
        </div>
        <span className="classtag">{f.class}</span>
        <svg className={`chev ${open ? "open" : ""}`} width="16" height="16" viewBox="0 0 16 16" fill="none">
          <path d="M6 4l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>

      {open && (
        <div className="fbody">
          <div className="kv">
            <span className="pill">
              id <b>{f.id}</b>
            </span>
            <span className="pill">
              confidence <b>{f.confidence.toFixed(2)}</b>
            </span>
            {f.attempts > 0 && (
              <span className="pill">
                attempts <b>{f.attempts}</b>
              </span>
            )}
            {verified && f.claimsProfit && (
              <span className="pill">
                attacker gain <b>{formatEth(f.valueFlowWei)}</b>
              </span>
            )}
            {verified && f.reentrancyConfirmed && (
              <span className="pill">
                mechanism <b>re-entry confirmed</b>
              </span>
            )}
          </div>

          {f.successAssertion && (
            <>
              <div className="block-label">Success invariant {verified ? "broken by the exploit" : "(guarded)"}</div>
              <div className="invariant">{f.successAssertion}</div>
            </>
          )}

          {f.evidenceNotes && f.evidenceNotes.length > 0 && (
            <>
              <div className="block-label">{verified ? "Evidence (from execution trace)" : "Why not confirmed"}</div>
              <ul className="evidence">
                {f.evidenceNotes.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </>
          )}

          {f.attackSteps && f.attackSteps.length > 0 && (
            <>
              <div className="block-label">Attack path</div>
              <ol className="steps">
                {f.attackSteps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </>
          )}

          {verified && f.poc && (
            <>
              <div className="block-label">Reproducible proof-of-concept</div>
              <Code src={f.poc} />
            </>
          )}

          {!verified && <p className="reason">{f.reason}</p>}
        </div>
      )}
    </div>
  );
}
