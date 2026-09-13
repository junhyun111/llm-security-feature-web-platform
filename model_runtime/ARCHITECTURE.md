# Runtime architecture

The production inference path has one responsibility per stage:

```text
SemanticStaticAnalyzer
  -> CandidateSelector
  -> Utility Router (rank 5, execute Top-2)
  -> ExpertRunner (initial Top-2)
  -> EvidenceEscalationPolicy
  -> ExpertRunner (remaining 3 only when required)
  -> ExpertAssessment (VULNERABLE / SAFE / UNCERTAIN)
  -> EvidenceGate (deterministic provenance checks)
  -> Deduplication
  -> Findings
```

`VulnerabilityPipeline` only orchestrates these stages. Ground-truth matching,
recall tracing, Router baselines, and calibration APIs live under
`llm_security.evaluation` and are not part of production inference.

The Router only ranks and selects the initial Top-2. It never predicts whether a
candidate needs all five Experts. `EvidenceEscalationPolicy` makes that decision
after real Top-2 responses: missing responses, UNCERTAIN, incomplete VULNERABLE
proof, or SAFE without valid counter-evidence cause a remaining-three pass.

Runtime metrics distinguish `escalation_requested_count` from
`full5_completed_count`; a failed remaining-three request is never reported as a
completed Full-5 review. Recall tracing separately records Top-2 coverage,
Top-2 positive assessments, and positive assessments after escalation.

## Assessment contract

Experts make the domain conclusion and return one `ExpertAssessment` for each
routed candidate. They must cite static evidence IDs and may record
counter-evidence; their stated confidence is retained for analysis but is never a
Finding threshold.

`EvidenceGate` only checks candidate attribution, routed Expert scope, CWE domain,
and cited evidence IDs. It does not make a second vulnerability judgement. SAFE and
UNCERTAIN assessments do not create Findings; a valid VULNERABLE assessment does.

The legacy decision layer remains in the source tree temporarily for offline
experiments, but production inference does not load `decision_layer.pt`.
