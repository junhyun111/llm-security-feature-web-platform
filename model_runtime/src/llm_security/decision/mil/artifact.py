from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import torch

from .calibration import PlattCalibrator
from .model import HierarchicalMIL, HierarchicalMILConfig


@dataclass(slots=True)
class MILArtifact:
    model: HierarchicalMIL
    calibrator: PlattCalibrator
    low_threshold: float
    high_threshold: float
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "hierarchical-mil-v1"

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        torch.save(
            {
                "schema_version": self.schema_version,
                "model_config": asdict(self.model.config),
                "model_state": self.model.state_dict(),
                "calibrator": self.calibrator.state_dict(),
                "low_threshold": float(self.low_threshold),
                "high_threshold": float(self.high_threshold),
                "metadata": dict(self.metadata),
            },
            destination,
        )

    @classmethod
    def load(
        cls, path: str | Path, *, map_location: str | torch.device = "cpu"
    ) -> "MILArtifact":
        try:
            payload = torch.load(
                Path(path), map_location=map_location, weights_only=True
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ValueError("MIL decision artifact is unreadable") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != "hierarchical-mil-v1":
            raise ValueError("MIL decision artifact schema is incompatible")
        config = HierarchicalMILConfig(**payload["model_config"])
        model = HierarchicalMIL(config)
        model.load_state_dict(payload["model_state"], strict=True)
        model.eval()
        low = float(payload["low_threshold"])
        high = float(payload["high_threshold"])
        if not 0.0 <= low <= high <= 1.0:
            raise ValueError("MIL artifact thresholds are invalid")
        return cls(
            model=model,
            calibrator=PlattCalibrator.from_state_dict(payload["calibrator"]),
            low_threshold=low,
            high_threshold=high,
            metadata=dict(payload.get("metadata", {})),
        )
