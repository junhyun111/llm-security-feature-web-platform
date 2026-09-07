"""Sample-level evidence decision layer."""

from .calibration import select_high_threshold
from .dataset import (
    grouped_train_validation_test_indices,
    grouped_train_calibration_threshold_indices,
    read_case_jsonl,
    write_case_jsonl,
    write_feature_csv,
)
from .features import DECISION_FEATURE_NAMES, EvidenceFeatureBuilder
from .mil import (
    CaseDecisionInput,
    CaseDecisionScore,
    DecisionInputBuilder,
    HierarchicalMIL,
    MILArtifact,
    MILTrainingConfig,
    PlattCalibrator,
    train_hierarchical_mil,
)
from .policy import DecisionPolicy
from .reporting import FindingReportBuilder
from .scorer import CalibratedFindingScorer, MILDecisionScorer

__all__ = [
    "CalibratedFindingScorer",
    "CaseDecisionInput",
    "CaseDecisionScore",
    "DECISION_FEATURE_NAMES",
    "DecisionInputBuilder",
    "DecisionPolicy",
    "EvidenceFeatureBuilder",
    "FindingReportBuilder",
    "HierarchicalMIL",
    "MILArtifact",
    "MILDecisionScorer",
    "MILTrainingConfig",
    "PlattCalibrator",
    "grouped_train_validation_test_indices",
    "grouped_train_calibration_threshold_indices",
    "read_case_jsonl",
    "select_high_threshold",
    "train_hierarchical_mil",
    "write_case_jsonl",
    "write_feature_csv",
]
