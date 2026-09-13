from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm_security.config import AppConfig
from llm_security_runtime.paths import RuntimePaths, configure_process_environment


class RuntimePathsTests(unittest.TestCase):
    def test_decision_artifact_is_not_configured_without_env_file(self) -> None:
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

                self.assertEqual("stale/path.pt", os.environ["DECISION_MODEL_PATH"])
                self.assertNotIn("artifacts\\decision_layer.pt", config.validation.decision_model_path or "")


if __name__ == "__main__":
    unittest.main()
