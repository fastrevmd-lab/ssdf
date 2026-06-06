"""Validate and rewrite LLM-supplied SQL for the guarded run_sql tool.

Layered defenses: single statement, SELECT-only, no SETTINGS clause, ssdf-only
tables, no table functions, enforced/clamped LIMIT. Returns safe SQL or raises.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp

ALLOWED_DB = "ssdf"
_DIALECT = "clickhouse"
_TABLE_FUNCTIONS = {
    "url", "file", "remote", "remotesecure", "s3", "s3cluster", "mysql",
    "postgresql", "jdbc", "odbc", "hdfs", "cluster", "merge", "input", "numbers",
    "generaterandom", "view", "dictionary",
}


class GuardError(ValueError):
    """Raised when a query is rejected by the guard."""


def guard_sql(query: str, max_limit: int = 1000) -> str:
    """Return rewritten safe SQL for a single read-only SELECT, or raise GuardError."""
    try:
        statements = sqlglot.parse(query, read=_DIALECT)
    except Exception as exc:
        raise GuardError(f"could not parse query: {exc}") from exc

    statements = [s for s in statements if s is not None]
    if len(statements) != 1:
        raise GuardError("exactly one statement is allowed")

    stmt = statements[0]
    if not isinstance(stmt, exp.Select):
        raise GuardError("only SELECT statements are allowed")

    if stmt.args.get("settings"):
        raise GuardError("SETTINGS clause is not allowed")

    for func in stmt.find_all(exp.Anonymous, exp.Func):
        name = (func.name or "").lower()
        if name in _TABLE_FUNCTIONS:
            raise GuardError(f"table function not allowed: {name}")

    tables = list(stmt.find_all(exp.Table))
    if not tables:
        raise GuardError("query must read from an ssdf table")
    for table in tables:
        # A table function (e.g. url(...)) parses as Table wrapping an
        # Anonymous/Func with no db/name; reject anything not a plain ssdf table.
        if not isinstance(table.this, exp.Identifier):
            raise GuardError("table functions are not allowed")
        db = (table.db or "").lower()
        if db != ALLOWED_DB:
            raise GuardError(
                f"only the '{ALLOWED_DB}' database is allowed (got {table.db or 'unqualified'}.{table.name})"
            )

    limit = stmt.args.get("limit")
    if limit is None:
        stmt = stmt.limit(max_limit)
    else:
        expr = limit.expression
        if isinstance(expr, exp.Literal) and expr.is_int:
            if int(expr.name) > max_limit:
                stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))
        else:
            stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))

    return stmt.sql(dialect=_DIALECT)
