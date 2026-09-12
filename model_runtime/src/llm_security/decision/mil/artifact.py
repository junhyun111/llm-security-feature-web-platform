from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import torch

from .calibration import PlattCalibrator
from .model import (
    ContextualCandidateClassifier,
    ContextualCandidateClassifierConfig,
)


@dataclass(slots=True)
class CandidateDecisionArtifact:
    model: ContextualCandidateClassifier
    calibrator: PlattCalibrator
    candidate_threshold: float
    validation_threshold: float
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "candidate-decision-v2"

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
        if schema not in {"candidate-decision-v2", "hierarchical-mil-v1"}:
            raise ValueError("Candidate decision artifact schema is incompatible")
        config = ContextualCandidateClassifierConfig(**payload["model_config"])
        model = ContextualCandidateClassifier(config)
        state = dict(payload["model_state"])
        if schema == "hierarchical-mil-v1":
            state = {
                key: value
                for key, value in state.items()
                if not key.startswith("sample_head.") and key != "empty_candidate"
            }
        model.load_state_dict(state, strict=True)
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
            metadata={
                **dict(payload.get("metadata", {})),
                **(
                    {"migrated_from": "hierarchical-mil-v1"}
                    if schema == "hierarchical-mil-v1"
                    else {}
                ),
            },
        )
