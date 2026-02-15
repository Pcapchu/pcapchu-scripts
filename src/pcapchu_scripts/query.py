"""SQL query interface for the AI agent.

Exposes a single ``query()`` function that accepts raw SQL, runs it against
the DuckDB instance, and returns a typed :class:`QueryResult`.
"""

from __future__ import annotations

import logging

from pcapchu_scripts.db import Database
from pcapchu_scripts.errors import QueryError
from pcapchu_scripts.types import QueryResult

logger = logging.getLogger(__name__)

# Hard ceiling on returned rows to avoid blowing up agent context.
_MAX_ROWS = 50_000


def query(db: Database, sql: str, *, max_rows: int = _MAX_ROWS) -> QueryResult:
    """Execute *sql* and return a :class:`QueryResult`.

    Parameters:
        db: An open :class:`Database` handle.
        sql: Arbitrary read SQL (SELECT, PRAGMA, DESCRIBE, …).
        max_rows: Safety limit; results beyond this are truncated.

    Raises:
        QueryError: On any DuckDB execution failure.
    """
    logger.info("executing query: %s", sql[:200])

    try:
        cursor = db.execute(sql)
    except Exception as exc:
        raise QueryError(f"query execution failed: {exc}") from exc

    if cursor.description is None:
        # DDL / DML with no result set.
        return QueryResult(columns=[], types=[], rows=[], row_count=0)

    columns = [desc[0] for desc in cursor.description]
    types = [str(desc[1]) for desc in cursor.description]
    rows = [list(r) for r in cursor.fetchmany(max_rows)]

    result = QueryResult(columns=columns, types=types, rows=rows, row_count=len(rows))
    logger.info("query returned %d row(s), %d column(s)", result.row_count, len(result.columns))
    return result
