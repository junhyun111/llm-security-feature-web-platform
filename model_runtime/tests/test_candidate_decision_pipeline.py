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
    CandidateDecisionTrainingConfig,
    DecisionInputBuilder,
    DecisionPolicy,
    NormalityGuidedDSMIL,
    PlattCalibrator,
    BagTrainingExample,
    bag_examples_from_cases,
    read_case_jsonl,
    select_candidate_threshold,
    write_case_jsonl,
    train_candidate_decision_model,
)
from llm_security.decision.mil.losses import ng_dsmil_loss
from llm_security.decision.mil.model import CandidateForwardOutput
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


class FixedForwardModel:
    """Deterministic score source for scorer calibration-contract tests."""

    def eval(self) -> None:
        return None

    def __call__(self, case) -> CandidateForwardOutput:
        size = len(case.candidates)
        return CandidateForwardOutput(
            candidate_logits=torch.zeros(size),
            bag_logit=torch.tensor(0.0),
            sample_logit=torch.tensor(0.0),
            candidate_attention=torch.full((size,), 1.0 / max(1, size)),
            bundle_attention=[torch.empty(0) for _ in case.candidates],
            candidate_embeddings=torch.empty(size, 64),
            normality_similarity=torch.empty(size),
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

    def test_candidate_logits_are_independent_of_other_candidates(self) -> None:
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
        model = NormalityGuidedDSMIL()
        model.eval()

        with torch.no_grad():
            one_logit = model(one).candidate_logits[0]
            two_logit = model(two).candidate_logits[0]

        self.assertTrue(torch.allclose(one_logit, two_logit, atol=1e-6))

    def test_ng_dsmil_loss_uses_one_label_per_bag(self) -> None:
        first = candidate("C1")
        second = candidate("C2", file="other.c", function="other")
        positive = DecisionInputBuilder().build(
            case_id="MIL-001-V",
            candidates=[first],
            routes=[route("C1")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )
        negative = DecisionInputBuilder().build(
            case_id="MIL-002-S",
            candidates=[second],
            routes=[route("C2")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )
        model = NormalityGuidedDSMIL()
        loss = ng_dsmil_loss([model(positive), model(negative)], [1, 0])
        loss.backward()

        self.assertGreater(float(loss.detach()), 0.0)

    def test_artifact_and_output_have_no_top_candidate_schema(self) -> None:
        artifact = CandidateDecisionArtifact(
            NormalityGuidedDSMIL(),
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

    def test_only_project_probability_uses_bag_calibration(self) -> None:
        case = DecisionInputBuilder().build(
            case_id="S1",
            candidates=[candidate("C1")],
            routes=[route("C1")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
        )
        output = CandidateDecisionModel(
            FixedForwardModel(),  # type: ignore[arg-type]
            PlattCalibrator(0.0, 2.0),
            candidate_threshold=0.2,
            validation_threshold=0.8,
        ).predict(case)

        self.assertAlmostEqual(0.5, output.candidate_probabilities["C1"])
        self.assertAlmostEqual(0.880797, output.project_probability, places=5)

    def test_candidate_threshold_preserves_target_recall(self) -> None:
        threshold = select_candidate_threshold(
            [0.92, 0.75, 0.80], [1, 1, 0], target_recall=0.5
        )

        self.assertEqual(0.92, threshold)

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

    def test_nested_jsonl_reuses_features_without_candidate_labels(self) -> None:
        case = DecisionInputBuilder().build(
            case_id="S1",
            candidates=[candidate("C1")],
            routes=[route("C1")],
            bundles=[],
            expert_output=SimpleNamespace(failures=[]),
            project_id="project",
            cve_id="CVE-1",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decision.jsonl"
            write_case_jsonl(path, [case])
            restored = read_case_jsonl(path)

        self.assertIsNone(restored[0].candidates[0].label)

    def test_bag_examples_infer_existing_mil_case_suffixes(self) -> None:
        builder = DecisionInputBuilder()
        output = SimpleNamespace(failures=[])
        cases = [
            builder.build(
                case_id="MIL-00001-V",
                candidates=[candidate("C1")],
                routes=[route("C1")],
                bundles=[],
                expert_output=output,
            ),
            builder.build(
                case_id="MIL-00002-S",
                candidates=[candidate("C2")],
                routes=[route("C2")],
                bundles=[],
                expert_output=output,
            ),
        ]

        examples = bag_examples_from_cases(cases)

        self.assertEqual([1, 0], [example.label for example in examples])

    def test_training_uses_bag_labels_without_candidate_labels(self) -> None:
        builder = DecisionInputBuilder()
        output = SimpleNamespace(failures=[])
        positive = BagTrainingExample(
            case=builder.build(
                case_id="MIL-00001-V",
                candidates=[candidate("C1", score=0.9)],
                routes=[route("C1")],
                bundles=[],
                expert_output=output,
            ),
            label=1,
        )
        negative = BagTrainingExample(
            case=builder.build(
                case_id="MIL-00002-S",
                candidates=[candidate("C2", score=0.1)],
                routes=[route("C2")],
                bundles=[],
                expert_output=output,
            ),
            label=0,
        )

        artifact = train_candidate_decision_model(
            [positive, negative],
            [positive, negative],
            [positive, negative],
            [positive, negative],
            config=CandidateDecisionTrainingConfig(
                epochs=2,
                batch_size=2,
                early_stop_patience=1,
            ),
        )

        self.assertEqual("normality-dsmil-v1", artifact.schema_version)
        self.assertGreaterEqual(artifact.validation_threshold, artifact.candidate_threshold)


if __name__ == "__main__":
    unittest.main()
