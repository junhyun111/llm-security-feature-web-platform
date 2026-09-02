from __future__ import annotations

from typing import Annotated

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from llm_security.models import to_dict
from llm_security.web.service import WebSettings

from .artifacts import inspect_artifacts
from .paths import RuntimePaths, configure_process_environment
from .request_service import RequestAwareWebJobService, RuntimeJobOptions


class PatchBatchRequest(BaseModel):
    finding_ids: list[str]
    model: str
    api_key: str


def create_runtime_app(
    paths: RuntimePaths | None = None,
) -> tuple[FastAPI, RequestAwareWebJobService]:
    selected = paths or RuntimePaths.discover()
    configure_process_environment(selected)
    startup_metadata = inspect_artifacts(selected)

    settings = WebSettings.from_env(selected.env_file)
    settings.env_file = selected.env_file
    settings.router_artifact = selected.router_artifact
    settings.workspace_root = selected.workspace_root

    service = RequestAwareWebJobService(settings)

    app = FastAPI(
        title="LLM Security Utility Router Runtime",
        version="0.2.0",
    )
    app.state.runtime_service = service
    app.state.runtime_paths = selected

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/runtime")
    def runtime_metadata() -> dict[str, object]:
        metadata = inspect_artifacts(selected)
        metadata["request_configuration"] = {
            "supports_sensitivity": True,
            "sensitivity_min": 0.0,
            "sensitivity_max": 1.0,
            "sensitivity_default": 0.5,
            "supports_request_api_key": True,
            "supports_request_model": True,
            "api_key_persistence": "process-memory-only",
        }
        return metadata

    @app.get("/api/runtime/startup")
    def startup() -> dict[str, object]:
        return startup_metadata

    @app.get("/api/jobs")
    def list_jobs() -> list[dict]:
        return [to_dict(item) for item in service.list_jobs()]

    @app.post("/api/jobs", status_code=status.HTTP_202_ACCEPTED)
    def upload_project(
        project_name: Annotated[str, Form()],
        relative_paths: Annotated[list[str], Form()],
        files: Annotated[list[UploadFile], File()],
        model: Annotated[str, Form()],
        api_key: Annotated[str, Form()],
        sensitivity: Annotated[float, Form()] = 0.5,
    ) -> dict:
        if len(files) != len(relative_paths):
            raise HTTPException(
                status_code=400,
                detail="Each uploaded file must have one relative path",
            )

        if not 0.0 <= sensitivity <= 1.0:
            raise HTTPException(
                status_code=400,
                detail="sensitivity must be between 0.0 and 1.0",
            )

        selected_model = _normalize_optional(model)
        selected_api_key = _normalize_optional(api_key)

        if selected_model is None or len(selected_model) > 200 or any(
            character in "\r\n" for character in selected_model
        ):
            raise HTTPException(status_code=400, detail="Invalid OpenRouter model ID")

        if selected_api_key is None or len(selected_api_key) > 512 or any(
            character.isspace() for character in selected_api_key
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid OpenRouter API Key format",
            )

        router_metadata = startup_metadata.get("router", {})
        trained_models = router_metadata.get("expert_model_ids", []) \
            if isinstance(router_metadata, dict) else []

        try:
            record = service.create_job(
                project_name,
                [
                    (relative, upload.file)
                    for relative, upload in zip(
                        relative_paths,
                        files,
                        strict=True,
                    )
                ],
                options=RuntimeJobOptions(
                    sensitivity=sensitivity,
                    model=selected_model,
                    api_key=selected_api_key,
                    router_validated=selected_model in trained_models,
                ),
            )
            return to_dict(record)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error),
            ) from error

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict:
        try:
            return to_dict(service.get_job(job_id))
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail="Job not found",
            ) from error

    @app.delete("/api/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_job(job_id: str) -> None:
        try:
            service.delete_job(job_id)
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail="Job not found",
            ) from error
        except RuntimeError as error:
            raise HTTPException(
                status_code=409,
                detail=str(error),
            ) from error

    @app.get("/api/jobs/{job_id}/analysis")
    def get_analysis(job_id: str) -> dict:
        try:
            analysis = service.get_analysis(job_id)

            for bundle in analysis.get("findings", []):
                finding_id = bundle["finding"]["finding_id"]
                patch = service.get_patch(job_id, finding_id)
                bundle["patch"] = to_dict(patch) if patch else None

            patch_batch = service.get_patch_batch(job_id)
            analysis["patch_batch"] = (
                to_dict(patch_batch)
                if patch_batch
                else None
            )
            return analysis
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail="Job not found",
            ) from error
        except RuntimeError as error:
            raise HTTPException(
                status_code=409,
                detail=str(error),
            ) from error

    @app.get("/api/jobs/{job_id}/files")
    def list_project_files(
        job_id: str,
        version: str = "original",
    ) -> list[dict]:
        try:
            return service.list_project_files(job_id, version=version)
        except (KeyError, FileNotFoundError) as error:
            raise HTTPException(status_code=404, detail="Project source not found") from error
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/api/jobs/{job_id}/files/content")
    def get_project_file(
        job_id: str,
        path: str,
        version: str = "original",
    ) -> dict:
        try:
            return service.get_project_file(job_id, path, version=version)
        except (KeyError, FileNotFoundError) as error:
            raise HTTPException(status_code=404, detail="Source file not found") from error
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/api/jobs/{job_id}/patches/{patch_id}/preview/content")
    def get_patch_preview_file(
        job_id: str,
        patch_id: str,
        path: str,
    ) -> dict:
        try:
            return service.get_patch_preview_file(job_id, patch_id, path)
        except (KeyError, FileNotFoundError) as error:
            raise HTTPException(status_code=404, detail="Patch preview not found") from error
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/jobs/{job_id}/patches/proposal")
    def propose_patch_batch(
        job_id: str,
        request: PatchBatchRequest,
    ) -> dict:
        selected_model = _normalize_optional(request.model)
        selected_api_key = _normalize_optional(request.api_key)
        if selected_model is None or len(selected_model) > 200 or any(
            character in "\r\n" for character in selected_model
        ):
            raise HTTPException(status_code=400, detail="Invalid OpenRouter model ID")
        if selected_api_key is None or len(selected_api_key) > 512 or any(
            character.isspace() for character in selected_api_key
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid OpenRouter API Key format",
            )
        try:
            return to_dict(
                service.propose_patch_batch(
                    job_id,
                    request.finding_ids,
                    model=selected_model,
                    api_key=selected_api_key,
                )
            )
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail=str(error),
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error),
            ) from error
        except RuntimeError as error:
            raise HTTPException(
                status_code=409,
                detail=str(error),
            ) from error

    @app.post("/api/jobs/{job_id}/patches/{patch_id}/approve")
    def approve_patch_batch(job_id: str, patch_id: str) -> dict:
        try:
            return to_dict(
                service.approve_patch_batch(job_id, patch_id)
            )
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail=str(error),
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error),
            ) from error
        except RuntimeError as error:
            raise HTTPException(
                status_code=409,
                detail=str(error),
            ) from error

    @app.post("/api/jobs/{job_id}/patches/{patch_id}/reject")
    def reject_patch_batch(job_id: str, patch_id: str) -> dict:
        try:
            return to_dict(
                service.reject_patch_batch(job_id, patch_id)
            )
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail=str(error),
            ) from error
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail=str(error),
            ) from error

    @app.get("/api/jobs/{job_id}/download")
    def download_project(job_id: str) -> FileResponse:
        try:
            archive = service.create_download(job_id)
            project_name = service.get_job(job_id).project_name
            safe_name = "".join(
                character
                if character.isalnum() or character in "-_"
                else "-"
                for character in project_name
            ).strip("-") or "project"

            return FileResponse(
                archive,
                media_type="application/zip",
                filename=f"{safe_name}-reviewed.zip",
            )
        except KeyError as error:
            raise HTTPException(
                status_code=404,
                detail="Job not found",
            ) from error

    return app, service


def _normalize_optional(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None
