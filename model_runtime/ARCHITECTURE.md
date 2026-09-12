# Runtime architecture

The production inference path has one responsibility per stage:

```text
SemanticStaticAnalyzer
  -> CandidateSelector (rank + recall threshold + Top-K)
  -> BudgetedUtilityRouter (Top-2 + escalation)
  -> ExpertRunner
  -> EvidenceProcessor (structural validation + aggregation)
  -> CandidateDecisionModel (global context + candidate probabilities)
  -> EvidenceVerifier (counter-evidence + final verdict)
  -> Findings
```

`VulnerabilityPipeline` only orchestrates these stages. Ground-truth matching,
recall tracing, Router baselines, and calibration APIs live under
`llm_security.evaluation` and are not part of production inference.

## Decision contract

`CandidateDecisionOutput` contains candidate probabilities, an optional derived
project probability, and attention values for explanation. The project value is
derived as `1 - product(1 - candidate_probability)` and never controls whether a
Finding is emitted.

New training data must label every `CandidateDecisionInput`. The candidate model
uses binary cross-entropy over candidate logits; project/sample labels are not a
training objective.

The packaged `hierarchical-mil-v1` artifact can be read only as a transition aid.
Its obsolete sample-head weights are discarded and the artifact metadata records
`migrated_from=hierarchical-mil-v1`. Retrain and export a
`candidate-decision-v2` artifact before reporting calibrated candidate metrics.
