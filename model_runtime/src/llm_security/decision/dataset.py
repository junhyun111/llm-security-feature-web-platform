from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

import numpy as np
from sklearn.model_selection import GroupShuffleSplit

from .features import DECISION_FEATURE_NAMES
from .mil.schema import CaseDecisionInput


def write_case_jsonl(path: str | Path, cases: Iterable[CaseDecisionInput]) -> None:
    """Persist nested Sample→Candidate→Bundle training examples."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(case.to_dict(), ensure_ascii=False) + "\n")


def read_case_jsonl(path: str | Path) -> list[CaseDecisionInput]:
    cases: list[CaseDecisionInput] = []
    for line_number, raw_line in enumerate(
        Path(path).read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
            cases.append(CaseDecisionInput.from_dict(value))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid decision JSONL at line {line_number}") from exc
    return cases


def write_feature_csv(
    path: str | Path,
    rows: Iterable[Mapping[str, object]],
    *,
    metadata_fields: Sequence[str] = (
        "project_id",
        "cve_id",
        "candidate_id",
        "bundle_id",
        "label",
        "split",
    ),
) -> None:
    """Legacy diagnostic export; MIL training must use ``write_case_jsonl``."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [*metadata_fields, *DECISION_FEATURE_NAMES]
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def grouped_train_validation_test_indices(
    groups: Sequence[str],
    *,
    validation_fraction: float = 0.15,
    test_fraction: float = 0.15,
    random_state: int = 2026,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Split by project/CVE group so related code cannot leak across splits."""

    if not groups:
        raise ValueError("groups must not be empty")
    if validation_fraction <= 0 or test_fraction <= 0:
        raise ValueError("validation and test fractions must be positive")
    if validation_fraction + test_fraction >= 1:
        raise ValueError("validation and test fractions must sum to less than 1")
    values = np.asarray(groups)
    indices = np.arange(values.size)
    first = GroupShuffleSplit(
        n_splits=1,
        test_size=validation_fraction + test_fraction,
        random_state=random_state,
    )
    train_index, holdout_index = next(first.split(indices, groups=values))
    holdout_groups = values[holdout_index]
    validation_share = validation_fraction / (validation_fraction + test_fraction)
    second = GroupShuffleSplit(
        n_splits=1,
        test_size=1.0 - validation_share,
        random_state=random_state + 1,
    )
    validation_local, test_local = next(
        second.split(holdout_index, groups=holdout_groups)
    )
    validation_index = holdout_index[validation_local]
    test_index = holdout_index[test_local]
    return train_index, validation_index, test_index


def grouped_train_calibration_threshold_indices(
    groups: Sequence[str],
    *,
    calibration_fraction: float = 0.15,
    threshold_fraction: float = 0.15,
    random_state: int = 2026,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Named 70/15/15 split for MIL fit, Platt fit, and threshold selection."""

    return grouped_train_validation_test_indices(
        groups,
        validation_fraction=calibration_fraction,
        test_fraction=threshold_fraction,
        random_state=random_state,
    )
