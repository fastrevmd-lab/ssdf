"""Pin the CI test matrix to the services that actually exist.

CI covered `services/mcp-query` alone for the life of the repo, so 312 of its
tests never ran on a push or a pull request. Nothing failed -- the gap was
invisible, because a service with no workflow simply produces no red check.

That is the same failure shape as the eval registry drift (see
services/evals/tests/test_registry_drift.py): a list a human is asked to keep in
sync, which silently stops being in sync. So the matrix is pinned here rather
than trusted.

Parsed with a small line scan instead of PyYAML: `ssdf-common` has no YAML
dependency and this invariant is not worth adding one for.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# tests/ -> common/ -> services/ -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _REPO_ROOT / ".github/workflows/ci.yml"
_SERVICES = _REPO_ROOT / "services"


def _services_with_tests() -> set[str]:
    """Every services/* directory that is a real uv project with a test suite."""
    return {
        entry.name
        for entry in _SERVICES.iterdir()
        if (entry / "pyproject.toml").is_file() and (entry / "tests").is_dir()
    }


def _matrix_services() -> set[str]:
    """The `service:` list under the test job's matrix, as written in ci.yml."""
    if not _WORKFLOW.is_file():
        pytest.fail(f"no CI workflow at {_WORKFLOW}; every service is running unverified")

    lines = _WORKFLOW.read_text().splitlines()
    for index, line in enumerate(lines):
        if re.fullmatch(r"\s*service:\s*", line):
            found: set[str] = set()
            for entry in lines[index + 1 :]:
                match = re.fullmatch(r"\s*-\s*([A-Za-z0-9._-]+)\s*", entry)
                if not match:
                    break
                found.add(match.group(1))
            return found

    pytest.fail("ci.yml has no `service:` matrix list; the test job cannot be covering anything")


def test_ci_runs_the_tests_of_every_service():
    uncovered = _services_with_tests() - _matrix_services()
    assert not uncovered, (
        f"services with a test suite that CI never runs: {sorted(uncovered)}. "
        f"Add them to the `service:` matrix in .github/workflows/ci.yml -- an "
        f"uncovered service fails silently, by producing no check at all."
    )


def test_ci_matrix_does_not_name_services_that_do_not_exist():
    phantom = _matrix_services() - _services_with_tests()
    assert not phantom, (
        f"ci.yml runs a matrix leg for {sorted(phantom)}, which is not a service "
        f"with tests. That leg will fail or vacuously pass; remove it."
    )
