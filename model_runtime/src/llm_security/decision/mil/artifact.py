from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import torch

from .calibration import PlattCalibrator
from .model import (
    NormalityGuidedDSMIL,
    NormalityGuidedDSMILConfig,
)


@dataclass(slots=True)
class CandidateDecisionArtifact:
    model: NormalityGuidedDSMIL
    calibrator: PlattCalibrator
    candidate_threshold: float
    validation_threshold: float
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "normality-dsmil-v1"

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "schema_version": self.schema_version,
                "model_config": asdict(self.model.config),
                "model_state": self.model.state_dict(),
                "calibrator": self.calibrator.state_dict(),
                "candidate_threshold": float(self.candidate_threshold),
                "validation_threshold": float(self.validation_threshold),
                "metadata": dict(self.metadata),
            },
            destination,
        )

    @classmethod
    def load(
        cls, path: str | Path, *, map_location: str | torch.device = "cpu"
    ) -> "CandidateDecisionArtifact":
        try:
            payload = torch.load(
                Path(path), map_location=map_location, weights_only=True
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ValueError("Candidate decision artifact is unreadable") from exc
        schema = payload.get("schema_version") if isinstance(payload, dict) else None
        if schema != "normality-dsmil-v1":
            raise ValueError(
                "Decision model requires retraining with Normality-Guided DSMIL"
            )
        config = NormalityGuidedDSMILConfig(**payload["model_config"])
        model = NormalityGuidedDSMIL(config)
        model.load_state_dict(dict(payload["model_state"]), strict=True)
        model.eval()
        candidate_threshold = float(
            payload.get("candidate_threshold", payload.get("low_threshold"))
        )
        validation_threshold = float(
            payload.get("validation_threshold", payload.get("high_threshold"))
        )
        if not 0.0 <= candidate_threshold <= validation_threshold <= 1.0:
            raise ValueError("Candidate decision thresholds are invalid")
        return cls(
            model=model,
            calibrator=PlattCalibrator.from_state_dict(payload["calibrator"]),
            candidate_threshold=candidate_threshold,
            validation_threshold=validation_threshold,
            metadata=dict(payload.get("metadata", {})),
        )
