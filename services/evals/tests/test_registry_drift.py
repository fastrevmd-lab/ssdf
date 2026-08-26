"""Pin the eval tool registry to the MCP server's own tool registry.

`corpus.SOVEREIGN_TOOLS` gates the corpus lint: a question whose `required_tools`
are not in that set is rejected outright. So when a tool ships on the server but
is missing here, it becomes impossible to write eval coverage for it -- silently,
because nothing fails; the questions simply never get written.

That happened. `ingest_status`, `fabric_status`, `lab_topology_snapshot` and
`recent_alerts` were served for months while `corpus.py` still carried a comment
asking a human to keep the two lists in sync. This test replaces that comment.

`ssdf-evals` deliberately does NOT depend on `ssdf-mcp-query` -- the eval harness
scores a black-box MCP endpoint and must not import the implementation it grades.
So the server's registry is read from source with `ast` rather than imported. Only
the dict KEYS are needed, and those are plain string literals.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ssdf_evals.corpus import PUBLIC_TOOLS, SOVEREIGN_TOOLS

# tests/ -> evals/ -> services/ -> repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
_CLASSIFICATION = _REPO_ROOT / "services/mcp-query/src/ssdf_mcp_query/classification.py"


def _served_tool_names() -> frozenset[str]:
    """Return the keys of TOOL_DATA_CLASSES in services/mcp-query, via AST."""
    if not _CLASSIFICATION.is_file():
        pytest.fail(
            f"cannot find the server tool registry at {_CLASSIFICATION}. "
            "If mcp-query moved, update this path -- do not delete this test: "
            "it is the only thing keeping the eval corpus reachable to new tools."
        )

    tree = ast.parse(_CLASSIFICATION.read_text(), filename=str(_CLASSIFICATION))
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        targets = [node.target] if isinstance(node, ast.AnnAssign) else node.targets
        names = {t.id for t in targets if isinstance(t, ast.Name)}
        if "TOOL_DATA_CLASSES" not in names:
            continue
        if not isinstance(node.value, ast.Dict):
            pytest.fail("TOOL_DATA_CLASSES is no longer a dict literal; update this test")
        keys = [k for k in node.value.keys if isinstance(k, ast.Constant)]
        if len(keys) != len(node.value.keys):
            pytest.fail("TOOL_DATA_CLASSES has a non-literal key; update this test")
        return frozenset(str(k.value) for k in keys)

    pytest.fail("TOOL_DATA_CLASSES not found in services/mcp-query classification.py")


def test_every_served_tool_is_reachable_by_the_corpus():
    """A tool the server serves but the corpus cannot name is untestable."""
    missing = _served_tool_names() - SOVEREIGN_TOOLS
    assert not missing, (
        f"tools served by mcp-query but missing from corpus.SOVEREIGN_TOOLS: "
        f"{sorted(missing)}. Until they are added, no eval question may reference "
        f"them -- the corpus lint rejects unknown tools."
    )


def test_corpus_does_not_invent_tools_the_server_does_not_serve():
    """The reverse drift: a question could otherwise require a nonexistent tool."""
    invented = SOVEREIGN_TOOLS - _served_tool_names()
    assert not invented, (
        f"tools in corpus.SOVEREIGN_TOOLS that mcp-query does not serve: "
        f"{sorted(invented)}. A question requiring one can never pass its tool check."
    )


def test_public_tools_are_a_subset_of_sovereign_tools():
    """The public tier exposes a strict subset; nothing is public-only."""
    assert PUBLIC_TOOLS <= SOVEREIGN_TOOLS


def test_the_four_previously_stranded_tools_are_present():
    """Regression: these shipped served-but-unreachable. Keep them named."""
    stranded = {"ingest_status", "fabric_status", "lab_topology_snapshot", "recent_alerts"}
    assert stranded <= SOVEREIGN_TOOLS
