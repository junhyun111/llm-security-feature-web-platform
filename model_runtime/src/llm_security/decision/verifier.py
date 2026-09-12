from __future__ import annotations

from dataclasses import dataclass

from ..models import (
    Candidate,
    EvidenceBundle,
    ExpertFamily,
    Finding,
    RouteDecision,
    UsageRecord,
    ValidationResult,
)
from ..validation import EvidenceFalsifier, EvidenceValidator
from .mil.schema import CandidateDecisionOutput
from .policy import DecisionPolicy
from .reporting import FindingReportBuilder


@dataclass(slots=True)
class VerificationOutput:
    findings: list[Finding]
    validations: list[ValidationResult]
    usage: list[UsageRecord]


class EvidenceVerifier:
    """Turn qualifying candidate decisions into independently verified findings."""

    def __init__(
        self,
        *,
        candidate_threshold: float,
        policy: DecisionPolicy,
        validator: EvidenceValidator,
        falsifier: EvidenceFalsifier | None = None,
        report_builder: FindingReportBuilder | None = None,
    ) -> None:
        self.candidate_threshold = candidate_threshold
        self.policy = policy
        self.validator = validator
        self.falsifier = falsifier or EvidenceFalsifier(
            client=validator.client,
            model=validator.model,
        )
        self.report_builder = report_builder or FindingReportBuilder()

    def verify(
        self,
        score: CandidateDecisionOutput,
        *,
        candidates: list[Candidate],
        routes: list[RouteDecision],
        bundles: list[EvidenceBundle],
    ) -> VerificationOutput:
        candidate_by_id = {
            candidate.candidate_id: candidate for candidate in candidates
        }
        route_by_id = {route.candidate_id: route for route in routes}
        bundles_by_candidate: dict[str, list[EvidenceBundle]] = {}
        for bundle in bundles:
            bundles_by_candidate.setdefault(bundle.candidate_id, []).append(bundle)

        findings: list[Finding] = []
        validations: list[ValidationResult] = []
        usage: list[UsageRecord] = []
        for candidate_id, probability in sorted(
            score.candidate_probabilities.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            if probability < self.candidate_threshold:
                continue
            candidate = candidate_by_id.get(candidate_id)
            route = route_by_id.get(candidate_id)
            if candidate is None or route is None:
                continue
            fallback_expert = next(
                iter(route.selected or list(route.scores)),
                ExpertFamily.CONTROL_STATE_ERROR,
            )
            candidate_bundles = sorted(
                bundles_by_candidate.get(candidate_id, []),
                key=lambda bundle: (
                    -score.bundle_attention.get(candidate_id, {}).get(
                        bundle.bundle_id, 0.0
                    ),
                    bundle.bundle_id,
                ),
            )
            for bundle in candidate_bundles or [None]:
                finding = self.report_builder.build(
                    score,
                    candidate,
                    bundle,
                    fallback_expert=fallback_expert,
                    probability=probability,
                )
                validation, falsifier_usage = self._verify_one(
                    finding, candidate, bundle, probability
                )
                findings.append(finding)
                validations.append(validation)
                usage.extend(falsifier_usage)
        return VerificationOutput(findings, validations, usage)

    def _verify_one(
        self,
        finding: Finding,
        candidate: Candidate,
        bundle: EvidenceBundle | None,
        probability: float,
    ) -> tuple[ValidationResult, list[UsageRecord]]:
        evidence_survives = bool(
            bundle
            and bundle.support_count > 0
            and bundle.evidence_ids
            and set(bundle.evidence_ids).issubset(
                {item.evidence_id for item in candidate.evidence}
            )
        )
        deterministic, _ = EvidenceFalsifier().run(finding, candidate)
        llm_falsified = False
        failed = False
        reason = deterministic.reason
        usage: list[UsageRecord] = []
        if deterministic.falsified:
            finding.evidence_against = _counter_evidence_lines(deterministic)
        elif (
            evidence_survives
            and probability < self.policy.validation_threshold
            and self.validator.use_llm_for_uncertain
            and self.falsifier.client is not None
            and self.falsifier.model
        ):
            try:
                falsification, record = self.falsifier.run(finding, candidate)
                if record is not None:
                    usage.append(record)
                llm_falsified = falsification.falsified
                reason = falsification.reason
                if llm_falsified:
                    finding.evidence_against = _counter_evidence_lines(falsification)
            except Exception as error:
                failed = True
                reason = "Falsifier failed: " + str(error)[:300]
        validation = self.policy.decide(
            finding_id=finding.finding_id,
            evidence_survives=evidence_survives,
            deterministic_counterproof=deterministic.falsified,
            llm_falsified=llm_falsified,
            falsifier_failed=failed,
            probability=probability,
        )
        validation.reasons.append(reason)
        return validation, usage


def _counter_evidence_lines(result) -> list[str]:
    return [
        f"{item.file}:{item.line}: {item.expression}"
        for item in result.counter_evidence
    ]
