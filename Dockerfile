# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.12.0 AS uv

FROM python:3.13-slim AS builder
ENV UV_NO_PROGRESS=1 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim AS runtime
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    QUERYATTEST_STATE_PATH=/app/state/queryattest.db

RUN groupadd --system --gid 10001 queryattest \
    && useradd --system --uid 10001 --gid queryattest --home-dir /nonexistent --shell /usr/sbin/nologin queryattest \
    && mkdir -p /app/state \
    && chown -R queryattest:queryattest /app

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY --chown=queryattest:queryattest config ./config
COPY --chown=queryattest:queryattest README.md LICENSE ./

USER 10001:10001
EXPOSE 8000
STOPSIGNAL SIGTERM
CMD ["queryattest-server"]
