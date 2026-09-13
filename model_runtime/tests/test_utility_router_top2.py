from __future__ import annotations

import unittest

from llm_security.models import (
    ACTIVE_UTILITY_EXPERTS,
    Candidate,
    Evidence,
    ExpertAssignment,
)
from llm_security.routing.utility import (
    AssignmentStatistics,
    BudgetedUtilityRouter,
)


class _FixedUtilityModel:
    def __init__(self, probabilities: dict[str, float]) -> None:
        self.probabilities = probabilities

    def predict_proba(self, _features: dict[str, float]) -> dict[str, float]:
        return self.probabilities


class UtilityRouterTop2Tests(unittest.TestCase):
    def test_router_ranks_five_but_selects_only_initial_top2(self) -> None:
        assignments = {
            expert.value: ExpertAssignment(expert, "test/model")
            for expert in ACTIVE_UTILITY_EXPERTS
        }
        router = BudgetedUtilityRouter(
            _FixedUtilityModel({
                ExpertAssignment(expert, "test/model").assignment_id: 1.0 - index * 0.1
                for index, expert in enumerate(ACTIVE_UTILITY_EXPERTS)
            }),
            {assignment.assignment_id: assignment for assignment in assignments.values()},
            {
                assignment.assignment_id: AssignmentStatistics(1, 1.0, 0.0, 0.0, 0.0)
                for assignment in assignments.values()
            },
        )
        candidate = Candidate(
            "C-1", "project", "copy.c", "copy", 1, 2, "memcpy(dst, src, n);",
            [Evidence("E-1", "memory_sink", "copy.c", 1, "memcpy", "copy")],
            {}, feature_schema_version="semantic-cwe-v3",
        )

        decision = router.route(candidate)

        self.assertEqual(5, len(decision.ranked_experts))
        self.assertEqual(2, len(decision.selected))
        self.assertEqual(decision.selected, decision.top2_experts)
        self.assertEqual("utility_top2", decision.policy)


if __name__ == "__main__":
    unittest.main()
