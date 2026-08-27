"""One version across the monorepo, enforced rather than asserted in a doc.

The root ``VERSION`` file is the number the repo publishes; every service's
``pyproject.toml`` is a separate declaration of it. They drifted once already:
the repo shipped v0.1.0, v0.1.1 and v0.1.2 while all eight services still read
``0.1.0``, because nothing connected the two and nobody had cause to look.

This is the same shape as the other two drift guards here -- a list a human is
asked to keep in sync, which quietly stops being in sync. When this fails, the
answer is to bump the versions, not to delete the test.

Bumping a service version also invalidates its ``uv.lock``, which records the
local package's own version. ``just setup`` runs ``uv sync --locked``, so a
forgotten re-lock breaks setup rather than failing here -- hence the second
test, which catches it in CI instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# tests/ -> common/ -> services/ -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_VERSION_FILE = _REPO_ROOT / "VERSION"
_SERVICES = _REPO_ROOT / "services"

_PYPROJECT_VERSION = re.compile(r'^version = "([^"]+)"$', re.M)
_LOCK_LOCAL_PACKAGE = re.compile(
    r'name = "(?P<name>ssdf-[a-z-]+)"\nversion = "(?P<version>[^"]+)"\n'
    r"source = \{ editable",
    re.M,
)


def _declared_version() -> str:
    if not _VERSION_FILE.is_file():
        pytest.fail(
            f"no {_VERSION_FILE}. It is the repo's published version and what "
            "inventory tooling reads; without it the repo reports no version."
        )
    return _VERSION_FILE.read_text().strip()


def _service_dirs() -> list[Path]:
    return sorted(d for d in _SERVICES.iterdir() if (d / "pyproject.toml").is_file())


def test_every_service_declares_the_repo_version():
    expected = _declared_version()
    drifted = {}
    for service in _service_dirs():
        match = _PYPROJECT_VERSION.search((service / "pyproject.toml").read_text())
        if match is None:
            pytest.fail(f"{service.name}/pyproject.toml has no version line")
        if match.group(1) != expected:
            drifted[service.name] = match.group(1)

    assert not drifted, (
        f"services disagree with VERSION ({expected}): {drifted}. "
        f"Bump them and re-run `uv lock` in each -- the lock records the local "
        f"package version too."
    )


def test_every_lockfile_records_the_repo_version_for_local_packages():
    """A bumped pyproject with a stale lock breaks `uv sync --locked`.

    That surfaces as a broken `just setup` for the next person rather than as a
    failure here, so it is worth catching in CI.
    """
    expected = _declared_version()
    stale = {}
    for service in _service_dirs():
        lock = service / "uv.lock"
        if not lock.is_file():
            continue
        for match in _LOCK_LOCAL_PACKAGE.finditer(lock.read_text()):
            if match.group("version") != expected:
                stale[f"{service.name}:{match.group('name')}"] = match.group("version")

    assert not stale, (
        f"lockfiles pin a stale local version (expected {expected}): {stale}. "
        f"Run `uv lock` in each affected service."
    )


def test_version_file_is_a_bare_semver():
    """No leading 'v', no trailing prose -- tooling reads this verbatim."""
    version = _declared_version()
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), (
        f"VERSION should be a bare x.y.z, got {version!r}. The git tag carries "
        f"the 'v' prefix; this file does not."
    )
