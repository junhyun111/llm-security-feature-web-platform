from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

from llm_security.models import to_dict
from llm_security.web.service import JobRecord, JobStatus, WebJobService, WebSettings


def record(status: JobStatus) -> JobRecord:
    return JobRecord(
        job_id="a" * 32,
        project_name="sample",
        status=status,
        created_at="2026-09-02T00:00:00+00:00",
        updated_at="2026-09-02T00:00:00+00:00",
    )


class RuntimeJobDeletionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.service = WebJobService(
            WebSettings(workspace_root=self.root, worker_count=1)
        )

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def write_job(self, item: JobRecord) -> Path:
        directory = self.root / item.job_id
        (directory / "input").mkdir(parents=True)
        (directory / "input" / "source.c").write_text("int main(void) {}")
        (directory / "analysis.json").write_text("{}")
        (directory / "job.json").write_text(
            json.dumps(to_dict(item)),
            encoding="utf-8",
        )
        return directory

    def test_completed_job_removes_all_runtime_files(self) -> None:
        directory = self.write_job(record(JobStatus.COMPLETED))

        self.service.delete_job("a" * 32)

        self.assertFalse(directory.exists())
        with self.assertRaises(KeyError):
            self.service.get_job("a" * 32)

    def test_active_job_cannot_be_deleted(self) -> None:
        directory = self.write_job(record(JobStatus.ANALYZING))

        with self.assertRaisesRegex(RuntimeError, "active analysis"):
            self.service.delete_job("a" * 32)

        self.assertTrue(directory.exists())

    def test_active_job_records_a_cancellation_request(self) -> None:
        self.write_job(record(JobStatus.ANALYZING))

        updated = self.service.cancel_job("a" * 32)

        self.assertEqual(JobStatus.CANCELLING, updated.status)
        self.assertTrue(self.service._is_cancel_requested("a" * 32))

    def test_cancelled_job_preserves_analysis_returned_before_shutdown(self) -> None:
        self.write_job(record(JobStatus.QUEUED))

        def partial_analysis(*args, **kwargs) -> dict:
            self.service._cancel_events.setdefault(
                "a" * 32,
                threading.Event(),
            ).set()
            return {
                "summary": {
                    "source_file_count": 1,
                    "finding_count": 1,
                    "validated_finding_count": 0,
                    "completed_expert_task_count": 1,
                    "expert_task_count": 2,
                },
                "findings": [{"finding": {"finding_id": "F-1"}}],
                "errors": [],
            }

        self.service._analysis_callback = partial_analysis
        self.service._run_analysis("a" * 32)

        updated = self.service.get_job("a" * 32)
        analysis = self.service.get_analysis("a" * 32)
        self.assertEqual(JobStatus.CANCELLED, updated.status)
        self.assertTrue(analysis["summary"]["cancelled"])
        self.assertEqual(1, len(analysis["findings"]))


if __name__ == "__main__":
    unittest.main()
