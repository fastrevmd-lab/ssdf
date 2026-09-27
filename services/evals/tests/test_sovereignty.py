"""Sovereign tier must refuse hosted-model runs (M16)."""

import pytest

from ssdf_evals.sovereignty import SovereigntyError, require_local_for_sovereign


def test_sovereign_local_true_passes():
    require_local_for_sovereign({"tier": "sovereign", "local": True, "run_id": "r", "model": "m"})


def test_sovereign_local_false_refused():
    with pytest.raises(SovereigntyError, match="r1"):
        require_local_for_sovereign(
            {"tier": "sovereign", "local": False, "run_id": "r1", "model": "claude-sonnet-4-6"}
        )


def test_public_tier_local_false_allowed():
    require_local_for_sovereign({"tier": "public", "local": False, "run_id": "r", "model": "m"})


def test_public_tier_local_true_allowed():
    require_local_for_sovereign({"tier": "public", "local": True, "run_id": "r", "model": "m"})
