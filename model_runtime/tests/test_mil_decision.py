from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import torch

from llm_security.aggregation import EvidenceAggregator
from llm_security.config import AppConfig
from llm_security.cwe import causal_cwe_family
from llm_security.decision import (
    DecisionInputBuilder,
    HierarchicalMIL,
    MILArtifact,
    MILDecisionScorer,
    PlattCalibrator,
    read_case_jsonl,
    write_case_jsonl,
)
from llm_security.decision.mil.losses import hierarchical_mil_loss
from llm_security.decision.mil.schema import CaseDecisionScore
from llm_security.factory import build_decision_components
from llm_security.models import (
    Candidate,
    Evidence,
    ExpertEvidence,
    ExpertFamily,
    GroundTruth,
    ProjectCase,
    RouteDecision,
    ValidationVerdict,
)
from llm_security.pipeline import VulnerabilityPipeline
from llm_security.routing import CandidateGate
from llm_security.validation import EvidenceValidator


def make_candidate(identifier: str = "C1", *, with_guard: bool = False) -> Candidate:
    evidence = [
        Evidence("E1", "memory_sink", "copy.c", 3, "memcpy(d,s,n)", "copy")
    ]
    if with_guard:
        evidence.append(
            Evidence(
                "E2",
                "guard_protects_sink",
                "copy.c",
                2,
                "if(n>8)return;",
                "copy",
                facts={"semantically_protective": True, "sink_line": 3},
            )
        )
    return Candidate(
        identifier,
        "project",
        "copy.c",
        "copy",
        1,
        4,
        "void copy(){\nif(n>8)return;\nmemcpy(d,s,n);\n}",
        evidence,
        {},
        0.9,
        feature_schema_version="semantic-cwe-v3",
    )


def route(candidate_id: str = "C1") -> RouteDecision:
    return RouteDecision(
        candidate_id,
        {ExpertFamily.MEMORY_SAFETY: 0.9},
        [ExpertFamily.MEMORY_SAFETY],
        0.9,
        0.4,
        "test",
        [],
    )


def observation() -> ExpertEvidence:
    return ExpertEvidence(
        "C1",
        ExpertFamily.MEMORY_SAFETY,
        "support",
        "buffer_bounds",
        ["CWE-787"],
        ["E1"],
        "n",
        "memcpy",
        ["n", "memcpy"],
        ["n > 8"],
        0.8,
    )


class FixedMILScorer:
    low_threshold = 0.28
    high_threshold = 0.71

    def score(self, case):
        candidate = case.candidates[0]
        bundle_id = candidate.bundles[0].bundle_id
        return CaseDecisionScore(
            case.sample_id,
            0.95,
            0.95,
            {candidate.candidate_id: 0.9},
            {candidate.candidate_id: 1.0},
            {candidate.candidate_id: {bundle_id: 1.0}},
            candidate.candidate_id,
            bundle_id,
        )


class FixedMultiCandidateScorer:
    low_threshold = 0.28
    high_threshold = 0.71

    def __init__(self, probabilities: dict[str, float]) -> None:
        self.probabilities = probabilities

    def score(self, case):
        bundle_attention = {
            candidate.candidate_id: {
                bundle.bundle_id: 1.0 / len(candidate.bundles)
                for bundle in candidate.bundles
            }
            for candidate in case.candidates
        }
        top_candidate_id = max(self.probabilities, key=self.probabilities.get)
        top_bundles = bundle_attention.get(top_candidate_id, {})
        return CaseDecisionScore(
            case.sample_id,
            0.05,
            0.05,
            dict(self.probabilities),
            {candidate.candidate_id: 0.5 for candidate in case.candidates},
            bundle_attention,
            top_candidate_id,
            next(iter(top_bundles), None),
        )


class HierarchicalMILTest(unittest.TestCase):
    def test_builder_and_model_retain_candidate_without_bundles(self) -> None:
        candidate = make_candidate()
        decision_input = DecisionInputBuilder().build(
            sample_id="S1",
            candidates=[candidate],
            routes=[route()],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )

        output = HierarchicalMIL()(decision_input)

        self.assertEqual(1, len(decision_input.candidates))
        self.assertEqual([], decision_input.candidates[0].bundles)
        self.assertEqual(torch.Size([]), output.sample_logit.shape)
        self.assertEqual(torch.Size([1]), output.candidate_logits.shape)

    def test_sample_loss_includes_safe_instance_and_ranking_terms(self) -> None:
        model = HierarchicalMIL()
        safe = DecisionInputBuilder().build(
            sample_id="safe",
            candidates=[make_candidate()],
            routes=[route()],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )
        vulnerable = DecisionInputBuilder().build(
            sample_id="vulnerable",
            candidates=[make_candidate()],
            routes=[route()],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )
        outputs = [model(safe), model(vulnerable)]
        loss, parts = hierarchical_mil_loss(
            outputs, torch.tensor([0.0, 1.0]), ranking_margin=10.0
        )
        loss.backward()

        self.assertGreater(float(parts["bag_loss"]), 0.0)
        self.assertGreater(float(parts["negative_instance_loss"]), 0.0)
        self.assertGreater(float(parts["ranking_loss"]), 0.0)

    def test_artifact_roundtrip_and_sample_scorer(self) -> None:
        model = HierarchicalMIL()
        artifact = MILArtifact(model, PlattCalibrator(1.0, 0.0), 0.2, 0.8)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mil.pt"
            artifact.save(path)
            loaded = MILArtifact.load(path)
        case = DecisionInputBuilder().build(
            sample_id="S1",
            candidates=[make_candidate()],
            routes=[route()],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )

        score = MILDecisionScorer(
            loaded.model,
            loaded.calibrator,
            low_threshold=loaded.low_threshold,
            high_threshold=loaded.high_threshold,
        ).score(case)

        self.assertEqual("S1", score.sample_id)
        self.assertEqual("C1", score.top_candidate_id)
        self.assertIsNone(score.top_bundle_id)
        self.assertGreaterEqual(score.probability, 0.0)
        self.assertLessEqual(score.probability, 1.0)

    def test_high_score_is_rejected_by_deterministic_counterproof(self) -> None:
        candidate = make_candidate(with_guard=True)
        expert_output = SimpleNamespace(
            evidence=[observation()],
            findings=[],
            usage=[],
            errors=[],
            task_count=1,
            submitted_task_count=1,
            completed_task_count=1,
            failed_task_count=0,
            skipped_task_count=0,
            failures=[],
        )
        pipeline = VulnerabilityPipeline(
            analyzer=SimpleNamespace(analyze=lambda _case: [candidate]),
            router=SimpleNamespace(route=lambda _candidate: route()),
            expert_runner=SimpleNamespace(run=lambda _candidates, _routes: expert_output),
            aggregator=EvidenceAggregator(),
            validator=EvidenceValidator(use_llm_for_uncertain=False),
            mil_scorer=FixedMILScorer(),
        )

        result = pipeline.run(ProjectCase("S1", "project", {"copy.c": candidate.code}))

        self.assertEqual(ValidationVerdict.REJECTED, result.validations[0].verdict)
        self.assertTrue(result.validations[0].checks["deterministic_counterproof"])
        self.assertTrue(result.findings[0].evidence_against)

    def test_pipeline_emits_every_qualifying_candidate_and_cwe_bundle(self) -> None:
        first = make_candidate("C1")
        second = Candidate(
            "C2",
            "project",
            "parse.c",
            "parse",
            10,
            15,
            "int parse(void) { return size + 1; }",
            [Evidence("E2", "integer_arithmetic", "parse.c", 12, "size + 1", "parse")],
            {},
            0.8,
        )
        below_threshold = Candidate(
            "C3",
            "project",
            "safe.c",
            "safe",
            20,
            22,
            "int safe(void) { return 0; }",
            [],
            {},
            0.1,
        )
        observations = [
            observation(),
            ExpertEvidence(
                "C1",
                ExpertFamily.INTEGER_SIZE_TYPE,
                "support",
                causal_cwe_family("CWE-190"),
                ["CWE-190"],
                ["E1"],
                "n",
                "memcpy",
                ["n", "memcpy"],
                [],
                0.8,
            ),
            ExpertEvidence(
                "C2",
                ExpertFamily.INTEGER_SIZE_TYPE,
                "support",
                causal_cwe_family("CWE-190"),
                ["CWE-190"],
                ["E2"],
                "size",
                "size + 1",
                ["size", "size + 1"],
                [],
                0.8,
            ),
        ]
        expert_output = SimpleNamespace(
            evidence=observations,
            findings=[],
            usage=[],
            errors=[],
            task_count=3,
            submitted_task_count=3,
            completed_task_count=3,
            failed_task_count=0,
            skipped_task_count=0,
            failures=[],
        )
        routes = {
            "C1": RouteDecision(
                "C1",
                {
                    ExpertFamily.MEMORY_SAFETY: 0.9,
                    ExpertFamily.INTEGER_SIZE_TYPE: 0.8,
                },
                [ExpertFamily.MEMORY_SAFETY, ExpertFamily.INTEGER_SIZE_TYPE],
                0.9,
                0.1,
                "test",
                [],
            ),
            "C2": route("C2"),
            "C3": route("C3"),
        }
        pipeline = VulnerabilityPipeline(
            analyzer=SimpleNamespace(
                analyze=lambda _case: [first, second, below_threshold]
            ),
            router=SimpleNamespace(route=lambda candidate: routes[candidate.candidate_id]),
            expert_runner=SimpleNamespace(run=lambda _candidates, _routes: expert_output),
            aggregator=EvidenceAggregator(),
            validator=EvidenceValidator(use_llm_for_uncertain=False),
            mil_scorer=FixedMultiCandidateScorer(
                {"C1": 0.91, "C2": 0.84, "C3": 0.27}
            ),
        )

        result = pipeline.run(ProjectCase("S1", "project", {}))

        self.assertEqual(3, len(result.findings))
        self.assertEqual({"C1", "C2"}, {item.candidate_id for item in result.findings})
        self.assertEqual(
            {"CWE-787", "CWE-190"},
            {item.cwes[0] for item in result.findings if item.candidate_id == "C1"},
        )
        self.assertTrue(all(item.probability >= 0.84 for item in result.findings))
        self.assertTrue(
            all(
                item.checks["candidate_probability_scored"]
                for item in result.validations
            )
        )

    def test_pipeline_records_ground_truth_recall_by_stage(self) -> None:
        candidate = make_candidate()
        expert_output = SimpleNamespace(
            evidence=[observation()],
            findings=[],
            usage=[],
            errors=[],
            task_count=1,
            submitted_task_count=1,
            completed_task_count=1,
            failed_task_count=0,
            skipped_task_count=0,
            failures=[],
        )
        pipeline = VulnerabilityPipeline(
            analyzer=SimpleNamespace(analyze=lambda _case: [candidate]),
            router=SimpleNamespace(route=lambda _candidate: route()),
            expert_runner=SimpleNamespace(run=lambda _candidates, _routes: expert_output),
            aggregator=EvidenceAggregator(),
            validator=EvidenceValidator(use_llm_for_uncertain=False),
            mil_scorer=FixedMILScorer(),
        )
        case = ProjectCase(
            "S1",
            "project",
            {"copy.c": candidate.code},
            ground_truth=[
                GroundTruth(
                    "T1",
                    "copy.c",
                    "copy",
                    3,
                    3,
                    [ExpertFamily.MEMORY_SAFETY],
                    ["CWE-787"],
                ),
                GroundTruth(
                    "T2",
                    "missing.c",
                    "missing",
                    1,
                    1,
                    [ExpertFamily.MEMORY_SAFETY],
                    ["CWE-787"],
                ),
            ],
        )

        result = pipeline.run(case)

        self.assertIsNotNone(result.recall_trace)
        assert result.recall_trace is not None
        self.assertEqual(2, result.recall_trace.ground_truth_count)
        self.assertEqual(
            [
                "static_candidate",
                "candidate_gate",
                "ranker_top_k",
                "router",
                "expert_evidence",
                "mil_decision",
                "validator_validated",
            ],
            [stage.stage for stage in result.recall_trace.stages],
        )
        self.assertTrue(
            all(stage.retained_truth_ids == ["T1"] for stage in result.recall_trace.stages)
        )
        self.assertEqual({1: 0.5}, result.recall_trace.top_k_candidate_recall)
        self.assertEqual(
            ["T1"],
            result.recall_trace.validator_verdict_truth_ids["validated"],
        )

    def test_production_builder_requires_mil_artifact(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "Trained MIL decision model required"):
            build_decision_components(AppConfig())

    def test_gate_calibration_uses_vulnerable_sample_recall(self) -> None:
        calibration = CandidateGate.calibrate(
            [0.9, 0.1, 0.8, 0.95],
            [1, 1, 1, 0],
            sample_ids=["v1", "v1", "v2", "safe"],
            target_recall=1.0,
        )

        self.assertEqual(0.8, calibration.threshold)
        self.assertEqual(2, calibration.retained_vulnerable_sample_count)

    def test_nested_jsonl_preserves_sample_hierarchy(self) -> None:
        case = DecisionInputBuilder().build(
            sample_id="S1",
            candidates=[make_candidate()],
            routes=[route()],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
            label=1,
            project_id="project",
            cve_id="CVE-1",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decision.jsonl"
            write_case_jsonl(path, [case])
            restored = read_case_jsonl(path)

        self.assertEqual("S1", restored[0].sample_id)
        self.assertEqual(1, restored[0].label)
        self.assertEqual("C1", restored[0].candidates[0].candidate_id)
        self.assertEqual([], restored[0].candidates[0].bundles)

    def test_feature_collection_configuration_disables_gate_and_uses_top4(self) -> None:
        config = AppConfig()
        config.candidate_gate.enabled = True
        config.analysis.max_candidates_per_project = 12

        config.configure_decision_feature_collection()

        self.assertFalse(config.candidate_gate.enabled)
        self.assertEqual(4, config.analysis.max_candidates_per_project)


if __name__ == "__main__":
    unittest.main()
