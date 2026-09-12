from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import torch

from llm_security.aggregation import EvidenceAggregator
from llm_security.cwe import causal_cwe_family
from llm_security.decision import (
    CandidateDecisionArtifact,
    CandidateDecisionOutput,
    CandidateDecisionModel,
    DecisionInputBuilder,
    DecisionPolicy,
    ContextualCandidateClassifier,
    PlattCalibrator,
    read_case_jsonl,
    write_case_jsonl,
)
from llm_security.decision.mil.losses import candidate_classification_loss
from llm_security.decision.verifier import EvidenceVerifier
from llm_security.evaluation import RecallTracer
from llm_security.evidence_processing import EvidenceProcessor
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
from llm_security.selection import CandidateSelector
from llm_security.validation import EvidenceValidator


def candidate(
    identifier: str,
    *,
    file: str = "copy.c",
    function: str = "copy",
    line: int = 3,
    score: float = 0.9,
) -> Candidate:
    evidence_id = f"E-{identifier}"
    return Candidate(
        identifier,
        "project",
        file,
        function,
        line - 2,
        line + 1,
        "void f(void) { sink(value); }",
        [Evidence(evidence_id, "memory_sink", file, line, "sink(value)", function)],
        {},
        score,
        feature_schema_version="semantic-cwe-v3",
    )


def route(identifier: str) -> RouteDecision:
    return RouteDecision(
        identifier,
        {
            ExpertFamily.MEMORY_SAFETY: 0.9,
            ExpertFamily.INTEGER_SIZE_TYPE: 0.8,
        },
        [ExpertFamily.MEMORY_SAFETY, ExpertFamily.INTEGER_SIZE_TYPE],
        0.9,
        0.1,
        "test",
        [],
    )


def observation(identifier: str, cwe: str, expert: ExpertFamily) -> ExpertEvidence:
    return ExpertEvidence(
        identifier,
        expert,
        "support",
        causal_cwe_family(cwe),
        [cwe],
        [f"E-{identifier}"],
        "value",
        "sink",
        ["value", "sink"],
        [],
        0.8,
    )


class FixedDecisionModel:
    def __init__(self, probabilities: dict[str, float]) -> None:
        self.probabilities = probabilities

    def predict(self, case) -> CandidateDecisionOutput:
        return CandidateDecisionOutput(
            case_id=case.case_id,
            candidate_probabilities=dict(self.probabilities),
            project_probability=1.0,
            candidate_attention={
                candidate.candidate_id: 1.0 / len(case.candidates)
                for candidate in case.candidates
            },
            bundle_attention={
                candidate.candidate_id: {
                    bundle.bundle_id: 1.0 / max(1, len(candidate.bundles))
                    for bundle in candidate.bundles
                }
                for candidate in case.candidates
            },
        )


class CandidateDecisionPipelineTests(unittest.TestCase):
    def test_selector_owns_threshold_and_top_k(self) -> None:
        rows = [candidate("C1", score=0.9), candidate("C2", score=0.7), candidate("C3", score=0.2)]

        selection = CandidateSelector(
            threshold=0.4, threshold_enabled=True, max_candidates=1
        ).select(rows)

        self.assertEqual(["C1"], [item.candidate_id for item in selection.selected])
        self.assertEqual(
            ["C1", "C2"],
            [item.candidate_id for item in selection.threshold_candidates],
        )
        self.assertEqual({"C2", "C3"}, {item.candidate_id for item in selection.rejected})

    def test_selector_calibration_targets_vulnerable_sample_recall(self) -> None:
        calibration = CandidateSelector.calibrate(
            [0.9, 0.1, 0.8, 0.95],
            [1, 1, 1, 0],
            case_ids=["v1", "v1", "v2", "safe"],
            target_recall=1.0,
        )

        self.assertEqual(0.8, calibration.threshold)
        self.assertEqual(2, calibration.retained_vulnerable_case_count)

    def test_model_uses_global_context_for_candidate_logits(self) -> None:
        first = candidate("C1")
        second = candidate("C2", file="other.c", function="other", score=0.1)
        builder = DecisionInputBuilder()
        output = SimpleNamespace(failures=[])
        one = builder.build(
            case_id="one",
            candidates=[first],
            routes=[route("C1")],
            bundles=[],
            expert_output=output,
        )
        two = builder.build(
            case_id="two",
            candidates=[first, second],
            routes=[route("C1"), route("C2")],
            bundles=[],
            expert_output=output,
        )
        model = ContextualCandidateClassifier()
        model.eval()

        with torch.no_grad():
            one_logit = float(model(one).candidate_logits[0])
            two_logit = float(model(two).candidate_logits[0])

        self.assertNotEqual(one_logit, two_logit)

    def test_candidate_loss_uses_one_label_per_candidate(self) -> None:
        first = candidate("C1")
        second = candidate("C2", file="other.c", function="other")
        case = DecisionInputBuilder().build(
            case_id="labeled",
            candidates=[first, second],
            routes=[route("C1"), route("C2")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
            candidate_labels={"C1": 1, "C2": 0},
        )
        model = ContextualCandidateClassifier()
        output = model(case)
        loss = candidate_classification_loss(
            [output], [torch.tensor([1.0, 0.0])]
        )
        loss.backward()

        self.assertGreater(float(loss.detach()), 0.0)

    def test_artifact_and_output_have_no_top_candidate_schema(self) -> None:
        artifact = CandidateDecisionArtifact(
            ContextualCandidateClassifier(),
            PlattCalibrator(1.0, 0.0),
            0.2,
            0.8,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decision.pt"
            artifact.save(path)
            loaded = CandidateDecisionArtifact.load(path)
        case = DecisionInputBuilder().build(
            case_id="S1",
            candidates=[candidate("C1")],
            routes=[route("C1")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )

        output = CandidateDecisionModel(
            loaded.model,
            loaded.calibrator,
            candidate_threshold=loaded.candidate_threshold,
            validation_threshold=loaded.validation_threshold,
        ).predict(case)

        self.assertEqual({"C1"}, set(output.candidate_probabilities))
        self.assertFalse(hasattr(output, "top_candidate_id"))
        self.assertFalse(hasattr(output, "top_bundle_id"))

    def test_pipeline_emits_all_candidates_and_distinct_cwes(self) -> None:
        first = candidate("C1")
        second = candidate("C2", file="parse.c", function="parse", line=12)
        below = candidate("C3", file="safe.c", function="safe", score=0.1)
        expert_output = SimpleNamespace(
            evidence=[
                observation("C1", "CWE-787", ExpertFamily.MEMORY_SAFETY),
                observation("C1", "CWE-190", ExpertFamily.INTEGER_SIZE_TYPE),
                observation("C2", "CWE-190", ExpertFamily.INTEGER_SIZE_TYPE),
            ],
            usage=[],
            errors=[],
            task_count=3,
            submitted_task_count=3,
            completed_task_count=3,
            failed_task_count=0,
            skipped_task_count=0,
            failures=[],
        )
        pipeline = VulnerabilityPipeline(
            analyzer=SimpleNamespace(analyze=lambda _case: [first, second, below]),
            selector=CandidateSelector(threshold_enabled=False),
            router=SimpleNamespace(route=lambda item: route(item.candidate_id)),
            expert_runner=SimpleNamespace(run=lambda _c, _r: expert_output),
            evidence_processor=EvidenceProcessor(),
            decision_model=FixedDecisionModel({"C1": 0.91, "C2": 0.84, "C3": 0.27}),
            verifier=EvidenceVerifier(
                candidate_threshold=0.28,
                policy=DecisionPolicy(validation_threshold=0.71),
                validator=EvidenceValidator(use_llm_for_uncertain=False),
            ),
        )

        result = pipeline.run(ProjectCase("S1", "project", {}))

        self.assertEqual(3, len(result.findings))
        self.assertEqual({"C1", "C2"}, {item.candidate_id for item in result.findings})
        self.assertEqual(
            {"CWE-787", "CWE-190"},
            {item.cwes[0] for item in result.findings if item.candidate_id == "C1"},
        )
        self.assertTrue(
            all(
                validation.verdict == ValidationVerdict.VALIDATED
                for validation in result.validations
            )
        )

    def test_recall_trace_is_an_offline_evaluator(self) -> None:
        found = candidate("C1")
        expert_output = SimpleNamespace(
            evidence=[observation("C1", "CWE-787", ExpertFamily.MEMORY_SAFETY)],
            usage=[], errors=[], task_count=1, submitted_task_count=1,
            completed_task_count=1, failed_task_count=0, skipped_task_count=0,
            failures=[],
        )
        selector = CandidateSelector(threshold_enabled=False)
        selection = selector.select([found])
        pipeline = VulnerabilityPipeline(
            analyzer=SimpleNamespace(analyze=lambda _case: [found]),
            selector=selector,
            router=SimpleNamespace(route=lambda item: route(item.candidate_id)),
            expert_runner=SimpleNamespace(run=lambda _c, _r: expert_output),
            evidence_processor=EvidenceProcessor(),
            decision_model=FixedDecisionModel({"C1": 0.9}),
            verifier=EvidenceVerifier(
                candidate_threshold=0.28,
                policy=DecisionPolicy(validation_threshold=0.71),
                validator=EvidenceValidator(use_llm_for_uncertain=False),
            ),
        )
        result = pipeline.run(ProjectCase("S1", "project", {}))
        truths = [
            GroundTruth("T1", "copy.c", "copy", 3, 3, [ExpertFamily.MEMORY_SAFETY], ["CWE-787"]),
            GroundTruth("T2", "missing.c", "missing", 1, 1, [ExpertFamily.MEMORY_SAFETY], ["CWE-787"]),
        ]

        trace = RecallTracer().evaluate(
            ground_truth=truths, selection=selection, result=result
        )

        self.assertEqual(2, trace.ground_truth_count)
        self.assertTrue(
            all(stage.retained_truth_ids == ["T1"] for stage in trace.stages)
        )
        self.assertEqual({1: 0.5}, trace.top_k_candidate_recall)

    def test_nested_jsonl_preserves_candidate_labels(self) -> None:
        case = DecisionInputBuilder().build(
            case_id="S1",
            candidates=[candidate("C1")],
            routes=[route("C1")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
            candidate_labels={"C1": 1},
            project_id="project",
            cve_id="CVE-1",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decision.jsonl"
            write_case_jsonl(path, [case])
            restored = read_case_jsonl(path)

        self.assertEqual(1, restored[0].candidates[0].label)


if __name__ == "__main__":
    unittest.main()
