from __future__ import annotations

import unittest

from llm_security.aggregation import EvidenceAggregator
from llm_security.decision import (
    CalibratedFindingScorer,
    DecisionPolicy,
    EvidenceFeatureBuilder,
)
from llm_security.models import (
    Candidate,
    CounterEvidence,
    Evidence,
    ExpertEvidence,
    ExpertFamily,
    RouteDecision,
    ScoredEvidenceBundle,
    ValidationVerdict,
)
from llm_security.validation import EvidenceFalsifier


class Classifier:
    def predict_proba(self, _rows):
        return ProbabilityMatrix([[0.2, 0.8]])


class ProbabilityMatrix(list):
    def __getitem__(self, key):
        if isinstance(key, tuple):
            row, column = key
            return super().__getitem__(row)[column]
        return super().__getitem__(key)


class Calibrator:
    def transform(self, _values):
        return [0.72]


def candidate() -> Candidate:
    return Candidate(
        candidate_id="C-1",
        project_id="project",
        file="copy.c",
        function="copy",
        line_start=1,
        line_end=3,
        code="void copy(char *d, char *s, int n) {\nmemcpy(d, s, n);\n}",
        evidence=[
            Evidence("E1", "taint_source", "copy.c", 1, "n", "copy"),
            Evidence("E2", "memory_sink", "copy.c", 2, "memcpy(d, s, n)", "copy"),
        ],
        features={},
        suspicion_score=0.9,
        feature_schema_version="semantic-cwe-v3",
    )


class DecisionLayerTest(unittest.TestCase):
    def test_aggregation_keeps_confidence_as_features_not_probability(self) -> None:
        observations = [
            ExpertEvidence(
                candidate_id="C-1",
                expert=expert,
                position="support",
                vulnerability_family="buffer_bounds",
                cwes=["CWE-787"],
                evidence_ids=evidence_ids,
                source="n",
                sink="memcpy",
                trigger_path=["n", "memcpy"],
                preconditions=["n exceeds capacity"],
                self_confidence=confidence,
            )
            for expert, evidence_ids, confidence in [
                (ExpertFamily.MEMORY_SAFETY, ["E2"], 0.9),
                (ExpertFamily.TAINT_API_CONTRACT, ["E1", "E2"], 0.6),
            ]
        ]

        bundle = EvidenceAggregator().aggregate(observations, [candidate()])[0]

        self.assertEqual([0.9, 0.6], bundle.expert_confidences)
        self.assertEqual(["E1", "E2"], bundle.evidence_ids)
        self.assertEqual(3, bundle.total_evidence_references)
        self.assertFalse(hasattr(bundle, "probability"))

    def test_feature_map_distinguishes_unique_evidence_and_references(self) -> None:
        item = candidate()
        route = RouteDecision(
            candidate_id="C-1",
            scores={ExpertFamily.MEMORY_SAFETY: 0.8},
            selected=[ExpertFamily.MEMORY_SAFETY, ExpertFamily.TAINT_API_CONTRACT],
            top1_confidence=0.8,
            top1_top2_margin=0.3,
            policy="test",
            reasons=[],
        )
        observations = [
            ExpertEvidence(
                "C-1",
                ExpertFamily.MEMORY_SAFETY,
                "support",
                "buffer_bounds",
                ["CWE-787"],
                ["E2"],
                "n",
                "memcpy",
                ["n", "memcpy"],
                [],
                0.8,
            ),
            ExpertEvidence(
                "C-1",
                ExpertFamily.TAINT_API_CONTRACT,
                "support",
                "buffer_bounds",
                ["CWE-787"],
                ["E1", "E2"],
                "n",
                "memcpy",
                ["n", "memcpy"],
                [],
                0.7,
            ),
        ]
        bundle = EvidenceAggregator().aggregate(observations, [item])[0]

        features = EvidenceFeatureBuilder().build(bundle, item, route)

        self.assertEqual(2.0, features["unique_evidence_count"])
        self.assertAlmostEqual(2 / 3, features["evidence_diversity"])
        self.assertEqual(2.0, features["support_expert_count"])

    def test_calibrated_score_drives_two_threshold_policy(self) -> None:
        scorer = CalibratedFindingScorer(Classifier(), Calibrator())
        bundle = EvidenceAggregator().aggregate(
            [
                ExpertEvidence(
                    "C-1",
                    ExpertFamily.MEMORY_SAFETY,
                    "support",
                    "buffer_bounds",
                    ["CWE-787"],
                    ["E2"],
                    None,
                    "memcpy",
                    [],
                    [],
                    0.99,
                )
            ],
            [candidate()],
        )[0]
        probability = scorer.score({})
        scored = ScoredEvidenceBundle(bundle, probability, {})

        result = DecisionPolicy(low_threshold=0.28, high_threshold=0.71).decide_one(scored)

        self.assertEqual(0.72, probability)
        self.assertEqual(ValidationVerdict.VALIDATED, result.verdict)

    def test_low_probability_never_directly_rejects(self) -> None:
        bundle = EvidenceAggregator().aggregate(
            [
                ExpertEvidence(
                    "C-1",
                    ExpertFamily.MEMORY_SAFETY,
                    "unknown",
                    "buffer_bounds",
                    ["CWE-787"],
                    ["E2"],
                    None,
                    "memcpy",
                    [],
                    [],
                )
            ],
            [candidate()],
        )[0]
        result = DecisionPolicy().decide_one(ScoredEvidenceBundle(bundle, 0.05, {}))
        self.assertEqual(ValidationVerdict.UNCERTAIN, result.verdict)
        self.assertTrue(result.checks["below_low_threshold"])

    def test_counter_evidence_requires_exact_code_and_static_relation(self) -> None:
        item = candidate()
        item.evidence.append(
            Evidence(
                "E3",
                "guard_protects_sink",
                "copy.c",
                1,
                "void copy(char *d, char *s, int n) {",
                "copy",
                facts={"semantically_protective": True, "sink_line": 2},
            )
        )
        valid = CounterEvidence(
            "E3",
            "copy.c",
            1,
            "void copy(char *d, char *s, int n) {",
            "dominates_sink",
            2,
        )
        invented = CounterEvidence(
            "E4",
            "copy.c",
            1,
            "if (n < 10)",
            "dominates_sink",
            2,
        )

        self.assertTrue(EvidenceFalsifier.verify(valid, item))
        self.assertFalse(EvidenceFalsifier.verify(invented, item))


if __name__ == "__main__":
    unittest.main()
