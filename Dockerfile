FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-headless \
    semgrep \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-cache

COPY d1_triage/ ./d1_triage/
COPY d1_triage.py ./
COPY triage/ ./triage/
COPY training/ ./training/

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT ["python", "d1_triage.py"]
