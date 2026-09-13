# Runtime architecture

The production inference path has one responsibility per stage:

```text
SemanticStaticAnalyzer
  -> CandidateSelector
  -> Router
  -> ExpertRunner
  -> ExpertAssessment (VULNERABLE / SAFE / UNCERTAIN)
  -> EvidenceGate (deterministic provenance checks)
  -> Deduplication
  -> Findings
```

`VulnerabilityPipeline` only orchestrates these stages. Ground-truth matching,
recall tracing, Router baselines, and calibration APIs live under
`llm_security.evaluation` and are not part of production inference.

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
