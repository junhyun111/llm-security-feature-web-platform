from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PACKAGE_DIRECTORY = Path(__file__).resolve().parent
DEFAULT_RUNTIME_ROOT = PACKAGE_DIRECTORY.parents[1]


@dataclass(frozen=True, slots=True)
class RuntimePaths:
    """All mutable and replaceable files owned by the runtime bundle."""

    root: Path
    env_file: Path
    router_artifact: Path
    candidate_ranker_artifact: Path
    decision_artifact: Path
    workspace_root: Path

    @classmethod
    def discover(cls, env_file: str | Path | None = None) -> "RuntimePaths":
        root = Path(
            os.environ.get("LLM_SECURITY_RUNTIME_ROOT", DEFAULT_RUNTIME_ROOT)
        ).expanduser().resolve()
        selected_env = (
            Path(env_file).expanduser()
            if env_file is not None
            else Path(os.environ.get("LLM_SECURITY_RUNTIME_ENV", root / ".env"))
        )
        if not selected_env.is_absolute():
            selected_env = root / selected_env
        return cls(
            root=root,
            env_file=selected_env.resolve(),
            router_artifact=(root / "artifacts" / "router.pkl").resolve(),
            candidate_ranker_artifact=(
                root / "artifacts" / "candidate_ranker.pkl"
            ).resolve(),
            decision_artifact=(root / "artifacts" / "decision_layer.pt").resolve(),
            workspace_root=(root / "work").resolve(),
        )

    def require_artifacts(self) -> None:
        missing = [
            path
            for path in (
                self.router_artifact,
                self.candidate_ranker_artifact,
                self.decision_artifact,
            )
            if not path.is_file()
        ]
        if missing:
            raise FileNotFoundError(
                "Runtime artifact not found: " + ", ".join(str(path) for path in missing)
            )

    def require_env(self) -> None:
        if not self.env_file.is_file():
            raise FileNotFoundError(
                f"Runtime configuration not found: {self.env_file}. "
                "Standalone CLI analysis requires an explicit runtime env file."
            )


def configure_process_environment(paths: RuntimePaths) -> None:
    """Configure artifact and workspace paths for the packaged runtime."""

    # A runtime env file is optional for the web service. Per-request model and
    # API key values are supplied by the authenticated web application.
    if paths.env_file.is_file():
        for key, value in _read_env_file(paths.env_file).items():
            os.environ.setdefault(key, value)
    os.environ["CANDIDATE_RANKER_PATH"] = str(paths.candidate_ranker_artifact)
    os.environ["CANDIDATE_RANKER_REQUIRED"] = "true"
    os.environ["DECISION_MODEL_PATH"] = str(paths.decision_artifact)
    os.environ["WEB_ROUTER_ARTIFACT"] = str(paths.router_artifact)
    os.environ["WEB_WORKSPACE_ROOT"] = str(paths.workspace_root)


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid .env entry at line {line_number}")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values
