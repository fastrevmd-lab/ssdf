"""Sovereign-tier gate: the tier may only score local-model runs.

A hosted-model runner can leak live lab data (real IPs, real rule names)
into committed scorecards via reference_sql predicate lookups. Sovereign-tier
manifests must declare local=true; anything else is refused before scoring.
"""

from __future__ import annotations


class SovereigntyError(ValueError):
    """A sovereign-tier manifest declared a non-local model."""


def require_local_for_sovereign(manifest: dict) -> None:
    if manifest["tier"] == "sovereign" and not manifest["local"]:
        raise SovereigntyError(
            f"sovereign tier requires a local model; manifest {manifest['run_id']!r} "
            f"declares local=false for model {manifest['model']!r}"
        )
