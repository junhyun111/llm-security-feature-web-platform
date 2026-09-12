from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm_security.config import AppConfig
from llm_security_runtime.paths import RuntimePaths, configure_process_environment


class RuntimePathsTests(unittest.TestCase):
    def test_packaged_decision_artifact_is_configured_without_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(
                os.environ,
                {
                    "LLM_SECURITY_RUNTIME_ROOT": str(root),
                    "DECISION_MODEL_PATH": "stale/path.pt",
                },
            ):
                paths = RuntimePaths.discover()
                configure_process_environment(paths)
                config = AppConfig.from_env(paths.env_file)

                expected = str((root / "artifacts" / "decision_layer.pt").resolve())
                self.assertEqual(expected, os.environ["DECISION_MODEL_PATH"])
                self.assertEqual(expected, config.validation.decision_model_path)


if __name__ == "__main__":
    unittest.main()
