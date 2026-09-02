from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from llm_security.models import Candidate, ExpertFamily
from llm_security.prompts import finding_from_payload
from llm_security.web.service import load_project_sources


def candidate() -> Candidate:
    return Candidate(
        candidate_id="C-1",
        project_id="best-effort",
        file="fallback.c",
        function="fallback_function",
        line_start=10,
        line_end=20,
        code="int fallback_function(void) { return 0; }",
        evidence=[],
        features={},
    )


class BestEffortWebTest(unittest.TestCase):
    def test_relaxed_finding_parser_uses_candidate_location_defaults(self) -> None:
        payload = {
            "title": "Potential issue",
            "root_cause": "Unchecked value",
            "consequence": "Possible memory corruption",
            "confidence": 0.7,
        }

        finding = finding_from_payload(
            payload,
            index=1,
            candidate=candidate(),
            expert=ExpertFamily.MEMORY_BOUNDS,
            best_effort=True,
        )

        self.assertEqual("fallback.c", finding.file)
        self.assertEqual("fallback_function", finding.function)
        self.assertEqual(10, finding.line_start)
        self.assertEqual([], finding.evidence_ids)

        with self.assertRaises(KeyError):
            finding_from_payload(
                payload,
                index=1,
                candidate=candidate(),
                expert=ExpertFamily.MEMORY_BOUNDS,
            )

    def test_oversized_source_is_skipped_while_valid_source_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "small.c").write_text("int ok;", encoding="utf-8")
            (root / "large.cpp").write_text("x" * 100, encoding="utf-8")
            warnings: list[str] = []

            sources = load_project_sources(
                root,
                max_file_bytes=20,
                max_total_bytes=100,
                warnings=warnings,
            )

        self.assertEqual({"small.c": "int ok;"}, sources)
        self.assertEqual(1, len(warnings))
        self.assertIn("large.cpp", warnings[0])


if __name__ == "__main__":
    unittest.main()
