"""Public sample-level training API.

The former bundle-row LogisticRegression path is intentionally removed. Labels
belong to complete samples and are consumed by Hierarchical MIL.
"""

from .mil.artifact import MILArtifact
from .mil.training import MILTrainingConfig, train_hierarchical_mil

__all__ = ["MILArtifact", "MILTrainingConfig", "train_hierarchical_mil"]
