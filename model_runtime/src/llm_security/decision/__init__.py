"""Evidence-grounded candidate vulnerability decision layer."""

from .calibration import select_validation_threshold
from .dataset import (
    grouped_train_validation_test_indices,
    grouped_train_calibration_threshold_indices,
    read_case_jsonl,
    write_case_jsonl,
    write_feature_csv,
)
from .features import DECISION_FEATURE_NAMES, EvidenceFeatureBuilder
from .mil import (
    CandidateDecisionContext,
    CandidateDecisionArtifact,
    CandidateDecisionOutput,
    CandidateDecisionTrainingConfig,
    DecisionInputBuilder,
    ContextualCandidateClassifier,
    PlattCalibrator,
    train_candidate_decision_model,
)
from .policy import DecisionPolicy
from .reporting import FindingReportBuilder
from .scorer import CandidateDecisionModel

__all__ = [
    "CandidateDecisionArtifact",
    "CandidateDecisionModel",
    "CandidateDecisionOutput",
    "CandidateDecisionTrainingConfig",
    "CandidateDecisionContext",
    "DECISION_FEATURE_NAMES",
    "DecisionInputBuilder",
    "DecisionPolicy",
    "EvidenceFeatureBuilder",
    "FindingReportBuilder",
    "ContextualCandidateClassifier",
    "PlattCalibrator",
    "grouped_train_validation_test_indices",
    "grouped_train_calibration_threshold_indices",
    "read_case_jsonl",
    "select_validation_threshold",
    "train_candidate_decision_model",
    "write_case_jsonl",
    "write_feature_csv",
]
