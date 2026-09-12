# Runtime architecture

The production inference path has one responsibility per stage:

```text
SemanticStaticAnalyzer
  -> CandidateSelector (rank + recall threshold + Top-K)
  -> BudgetedUtilityRouter (Top-2 + escalation)
  -> ExpertRunner
  -> EvidenceProcessor (structural validation + aggregation)
  -> CandidateDecisionModel (NG-DSMIL candidate probabilities)
  -> EvidenceVerifier (counter-evidence + final verdict)
  -> Findings
```

`VulnerabilityPipeline` only orchestrates these stages. Ground-truth matching,
recall tracing, Router baselines, and calibration APIs live under
`llm_security.evaluation` and are not part of production inference.

## Decision contract

`CandidateDecisionOutput` contains independent raw-sigmoid candidate
probabilities, DSMIL critical-instance attention, and evidence attention for
explanation. Its project probability is Platt-calibrated from the DSMIL bag score
and never controls whether a Finding is emitted.

NG-DSMIL trains from one safety label per project bag. It combines DSMIL bag BCE,
safe-bag normal-prototype loss, and a max-instance ranking loss; candidate labels
are neither required nor consumed. Existing JSONL candidate and evidence features
remain compatible. Best-epoch and verifier-threshold selection use the raw
max-candidate probability, matching runtime decisions.

Only `normality-dsmil-v1` artifacts are accepted at inference. An older decision
artifact may warm-start the shared encoders during training, but it cannot be
loaded for production inference. Retrain and export a new artifact before running
the packaged runtime.
