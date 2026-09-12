from __future__ import annotations

from collections.abc import Sequence


def select_validation_threshold(
    probabilities: Sequence[float],
    labels: Sequence[int],
    *,
    max_fpr: float = 0.10,
) -> float:
    """Choose the recall-maximising threshold subject to an FPR ceiling."""

    if not 0.0 <= max_fpr <= 1.0:
        raise ValueError("max_fpr must be between 0 and 1")
    if len(probabilities) != len(labels) or not probabilities:
        raise ValueError("probabilities and labels must be non-empty and equal length")
    pairs = [(float(probability), int(label)) for probability, label in zip(probabilities, labels)]
    thresholds = sorted({1.0, 0.0, *(probability for probability, _ in pairs)}, reverse=True)
    positives = sum(label == 1 for _, label in pairs)
    negatives = sum(label == 0 for _, label in pairs)
    feasible: list[tuple[float, float]] = []
    for threshold in thresholds:
        tp = sum(probability >= threshold and label == 1 for probability, label in pairs)
        fp = sum(probability >= threshold and label == 0 for probability, label in pairs)
        recall = tp / max(1, positives)
        fpr = fp / max(1, negatives)
        if fpr <= max_fpr:
            feasible.append((recall, threshold))
    if not feasible:
        return 1.0
    # For equal recall, select the highest threshold to minimise accepted noise.
    return max(feasible, key=lambda item: (item[0], item[1]))[1]
