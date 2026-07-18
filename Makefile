.DEFAULT_GOAL := help

.PHONY: help sync lock lock-check format format-check lint typecheck unit coverage integration security dependency-audit build check clean

help:
	@printf '%s\n' \
	  'sync              Install the locked development environment' \
	  'lock              Regenerate uv.lock from public PyPI' \
	  'lock-check        Verify uv.lock is current and publish-safe' \
	  'format            Apply Ruff formatting' \
	  'format-check      Verify formatting without changing files' \
	  'lint              Run Ruff lint checks' \
	  'typecheck         Run strict mypy checks' \
	  'unit              Run tests that do not require PostgreSQL' \
	  'coverage          Run branch coverage with the enforced threshold' \
	  'integration       Run PostgreSQL integration tests (requires TEST_DATABASE_URL)' \
	  'security          Run source security checks (Bandit)' \
	  'dependency-audit  Query vulnerability databases with pip-audit (network required)' \
	  'build             Build wheel and source distribution' \
	  'check             Run all deterministic, offline quality gates' \
	  'clean             Remove generated caches and build output'

sync:
	uv sync --frozen --extra dev

lock:
	env -u UV_INDEX_URL uv lock --default-index https://pypi.org/simple

lock-check:
	env -u UV_INDEX_URL uv lock --check --offline --default-index https://pypi.org/simple

format:
	uv run --frozen ruff format .

format-check:
	uv run --frozen ruff format --check .

lint:
	uv run --frozen ruff check .

typecheck:
	uv run --frozen mypy src

unit:
	uv run --frozen pytest -m "not integration"

coverage:
	uv run --frozen pytest -m "not integration" --cov=queryattest --cov-branch --cov-report=term-missing:skip-covered

integration:
	@test -n "$$TEST_DATABASE_URL" || (echo 'TEST_DATABASE_URL is required' >&2; exit 2)
	uv run --frozen pytest -m integration

security:
	uv run --frozen bandit -q -r src/queryattest

dependency-audit:
	@if command -v uv >/dev/null 2>&1; then \
		uv run --frozen pip-audit; \
	elif [ -x .venv/bin/pip-audit ]; then \
		.venv/bin/pip-audit; \
	else \
		echo 'uv is not installed and .venv/bin/pip-audit is unavailable; run "uv sync --frozen --extra dev" first' >&2; \
		exit 127; \
	fi

build:
	uv build

check: lock-check format-check lint typecheck security coverage build

clean:
	rm -rf .coverage .pytest_cache .mypy_cache .ruff_cache htmlcov dist build
	find src tests -type d -name __pycache__ -prune -exec rm -rf {} +
