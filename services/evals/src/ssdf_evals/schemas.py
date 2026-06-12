"""Load + validate the contract schemas (manifest in, scorecard out).

The two JSON-Schema files under services/evals/schemas/ ARE the contract
runner projects code against; this module is the only validator.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


class SchemaError(ValueError):
    """A document does not conform to its contract schema."""


def _load(name: str) -> dict:
    return json.loads((SCHEMAS_DIR / name).read_text())


def _validate(obj: dict, schema_name: str) -> None:
    try:
        jsonschema.validate(obj, _load(schema_name))
    except jsonschema.ValidationError as exc:
        raise SchemaError(f"{schema_name}: {exc.message}") from exc


def validate_manifest(obj: dict) -> None:
    _validate(obj, "manifest.schema.json")


def validate_scorecard(obj: dict) -> None:
    _validate(obj, "scorecard.schema.json")
