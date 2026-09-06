"""Evidence-to-decision layer for the vulnerability pipeline."""

from .calibration import PlattCalibrator, select_high_threshold
from .features import DECISION_FEATURE_NAMES, EvidenceFeatureBuilder
from .dataset import grouped_train_validation_test_indices, write_feature_csv
from .policy import DecisionPolicy
from .reporting import FindingReportBuilder
from .scorer import CalibratedFindingScorer, LinearProbabilityClassifier
from .training import TrainedDecisionLayer, train_decision_layer

__all__ = [
    "CalibratedFindingScorer",
    "DECISION_FEATURE_NAMES",
    "DecisionPolicy",
    "EvidenceFeatureBuilder",
    "FindingReportBuilder",
    "TrainedDecisionLayer",
    "LinearProbabilityClassifier",
    "PlattCalibrator",
    "select_high_threshold",
    "grouped_train_validation_test_indices",
    "train_decision_layer",
    "write_feature_csv",
]
