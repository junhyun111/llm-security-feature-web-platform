FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    LLM_SECURITY_RUNTIME_ROOT=/app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY model_runtime/pyproject.toml ./pyproject.toml
COPY model_runtime/src ./src
COPY model_runtime/artifacts ./artifacts

RUN python -m pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/cpu "torch==2.8.0" \
    && python -m pip install --no-cache-dir .

RUN mkdir -p /app/work

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=60s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)" || exit 1

CMD ["llm-security-runtime", "serve", "--host", "0.0.0.0", "--port", "8000"]
