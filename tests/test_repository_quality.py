from __future__ import annotations

import re
import tomllib
from pathlib import Path
from urllib.parse import urlparse

import yaml

from queryattest import __version__

ROOT = Path(__file__).resolve().parents[1]
GENERATED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "htmlcov",
}


def repository_files(pattern: str):
    """Yield source-tree files while ignoring generated and third-party content."""
    for candidate in ROOT.rglob(pattern):
        relative_parts = candidate.relative_to(ROOT).parts
        if not GENERATED_DIRECTORIES.intersection(relative_parts):
            yield candidate


def test_release_metadata_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == __version__
    assert project["license"] == "Apache-2.0"
    assert "LICENSE" in project["license-files"]
    assert "Development Status :: 3 - Alpha" in project["classifiers"]


def test_public_project_identity_is_consistent() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["name"] == "queryattest"
    assert project["description"] == "Evidence-backed database execution for AI agents over MCP"
    assert project["scripts"] == {
        "queryattest": "queryattest.cli:app",
        "queryattest-server": "queryattest.server:main",
    }
    assert (ROOT / "src" / "queryattest" / "__init__.py").is_file()

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("# QueryAttest\n")
    assert "**Query Receipt**" in readme

    text_suffixes = {".md", ".py", ".toml", ".yaml", ".yml", ".json", ".sql", ".example"}
    legacy_references: list[str] = []
    for candidate in ROOT.rglob("*"):
        if not candidate.is_file():
            continue
        if any(
            part in {".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
            for part in candidate.parts
        ):
            continue
        if candidate.name in {"uv.lock", "LICENSE"} or candidate.suffix in text_suffixes:
            content = candidate.read_text(encoding="utf-8")
            if ("veri" + "data") in content.casefold():
                legacy_references.append(str(candidate.relative_to(ROOT)))
    assert not legacy_references


def test_repository_contains_required_quality_documents() -> None:
    required = {
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "GOVERNANCE.md",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "docs/publishing.md",
        "docs/quality-gates.md",
        "docs/threat-model.md",
    }
    assert not [path for path in sorted(required) if not (ROOT / path).is_file()]

    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
    assert len(license_text) > 10_000


def test_ci_workflow_contains_all_quality_jobs() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    assert {"unit", "static-analysis", "postgres-integration", "package", "container"} <= set(jobs)

    static_steps = "\n".join(
        str(step.get("run", ""))
        for step in jobs["static-analysis"]["steps"]
        if isinstance(step, dict)
    )
    for required_command in (
        "uv lock --check --offline",
        "ruff format --check",
        "ruff check",
        "mypy src",
        "bandit",
        "--cov-branch",
        "pip-audit",
    ):
        assert required_command in static_steps

    integration_steps = "\n".join(
        str(step.get("run", ""))
        for step in jobs["postgres-integration"]["steps"]
        if isinstance(step, dict)
    )
    assert "demo/init.sql" in integration_steps
    assert "pytest -m integration" in integration_steps

    for job_name, job in jobs.items():
        assert job.get("timeout-minutes"), job_name
        for step in job.get("steps", []):
            action = step.get("uses") if isinstance(step, dict) else None
            if action is not None:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), action


def test_quality_configuration_is_enforced() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]
    assert config["coverage"]["run"]["branch"] is True
    assert config["coverage"]["report"]["fail_under"] >= 80
    assert "error::ResourceWarning" in config["pytest"]["ini_options"]["filterwarnings"]
    assert "S" in config["ruff"]["lint"]["select"]
    assert config["mypy"]["strict"] is True


def test_makefile_exposes_canonical_quality_targets() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in (
        "lock-check:",
        "format-check:",
        "lint:",
        "typecheck:",
        "coverage:",
        "security:",
        "dependency-audit:",
        "integration:",
        "build:",
        "check:",
    ):
        assert target in makefile


def test_public_repository_hygiene() -> None:
    required = {
        ".dockerignore",
        ".editorconfig",
        ".gitattributes",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/dependabot.yml",
    }
    assert not [path for path in sorted(required) if not (ROOT / path).is_file()]

    lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    lock_urls = re.findall(r'https://[^"\s}]+', lock_text)
    lock_hosts = {urlparse(url).hostname for url in lock_urls}
    assert lock_hosts == {"pypi.org", "files.pythonhosted.org"}
    assert "https://pypi.org/simple" in lock_text
    assert "https://files.pythonhosted.org/packages/" in lock_text

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for ignored in (".env", ".queryattest/", ".venv/", "dist/", "*.egg-info/"):
        assert ignored in gitignore


def test_github_forms_and_dependency_updates_parse() -> None:
    for path in (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/dependabot.yml",
    ):
        parsed = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
        assert isinstance(parsed, dict), path

    dependabot = yaml.safe_load((ROOT / ".github/dependabot.yml").read_text(encoding="utf-8"))
    ecosystems = {update["package-ecosystem"] for update in dependabot["updates"]}
    assert ecosystems == {"pip", "github-actions", "docker"}


def test_container_is_reproducible_and_non_root() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ghcr.io/astral-sh/uv:0.10.0" in dockerfile
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "PYTHONDONTWRITEBYTECODE=1" in dockerfile
    assert "QUERYATTEST_STATE_PATH=/app/state/queryattest.db" in dockerfile

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    mcp = compose["services"]["mcp"]
    assert mcp["read_only"] is True
    assert "ALL" in mcp["cap_drop"]
    assert "no-new-privileges:true" in mcp["security_opt"]

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for excluded in (".env", ".venv", ".queryattest", "dist", "tests"):
        assert excluded in dockerignore

    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    container_steps = "\n".join(
        str(step.get("run", ""))
        for step in workflow["jobs"]["container"]["steps"]
        if isinstance(step, dict)
    )
    assert "docker build" in container_steps
    assert "Config.User" in container_steps
    assert "10001:10001" in container_steps


def test_local_markdown_links_resolve() -> None:
    missing: list[str] = []
    link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    for document in repository_files("*.md"):
        for raw_target in link_pattern.findall(document.read_text(encoding="utf-8")):
            target = raw_target.strip().split()[0].strip("<>")
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            path_part = target.split("#", maxsplit=1)[0]
            if path_part and not (document.parent / path_part).resolve().exists():
                missing.append(f"{document.relative_to(ROOT)} -> {target}")
    assert not missing
