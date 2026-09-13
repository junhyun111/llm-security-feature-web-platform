from __future__ import annotations

import unittest

from llm_security.analysis import SemanticStaticAnalyzer
from llm_security.cwe import cwe_category
from llm_security.evaluation.recall_trace import _cwes_match
from llm_security.models import ProjectCase


class AllFunctionCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        # The test runner currently has Tree-sitter 0.26, which removed the
        # timeout_micros setter used by the production-pinned 0.25 release.
        self.analyzer = SemanticStaticAnalyzer(parse_timeout_ms=None)

    def test_non_security_function_is_still_a_candidate(self) -> None:
        case = ProjectCase(
            case_id="all-functions",
            project_id="test",
            source_files={
                "math.c": """
                    int add(int a, int b) {
                        return a + b;
                    }
                """,
            },
        )

        candidates = self.analyzer.analyze(case)

        self.assertEqual(1, len(candidates))
        self.assertEqual("add", candidates[0].function)

    def test_memory_access_is_normalized_as_evidence(self) -> None:
        case = ProjectCase(
            case_id="memory-evidence",
            project_id="test",
            source_files={
                "read.c": """
                    int read(int *a, int i) {
                        return a[i];
                    }
                """,
            },
        )

        candidates = self.analyzer.analyze(case)

        self.assertEqual(1, len(candidates))
        self.assertTrue(
            any(item.kind == "memory_access" for item in candidates[0].evidence)
        )

    def test_cwe_family_matching_accepts_related_memory_cwes(self) -> None:
        self.assertTrue(_cwes_match(["CWE-787"], ["CWE-119"]))
        self.assertFalse(_cwes_match(["CWE-787"], ["CWE-78"]))
        self.assertEqual("integer", cwe_category("CWE-189"))


if __name__ == "__main__":
    unittest.main()
