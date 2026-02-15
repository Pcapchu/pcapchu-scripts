"""DuckDB database lifecycle management.

Thin wrapper that owns the connection and provides explicit open/close
semantics — no hidden global state (Go-style resource management).
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import TracebackType

import duckdb

from pcapchu_scripts.errors import DatabaseError

logger = logging.getLogger(__name__)

# Sentinel for an in-memory database.
IN_MEMORY = ":memory:"


class Database:
    """Manages a single DuckDB connection.

    Usage::

        with Database("/data/pcapchu-scripts.duckdb") as db:
            db.execute("SELECT 1")

    Or without context manager — caller must call ``close()`` explicitly.
    """

    __slots__ = ("_conn", "_path")

    def __init__(self, path: str | Path = IN_MEMORY) -> None:
        self._path = str(path)
        try:
            self._conn: duckdb.DuckDBPyConnection = duckdb.connect(self._path)
        except duckdb.Error as exc:
            raise DatabaseError(f"failed to open database at {self._path}: {exc}") from exc
        logger.info("database opened: %s", self._path)

    # -- context manager -------------------------------------------------------

    def __enter__(self) -> Database:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- public API ------------------------------------------------------------

    @property
    def conn(self) -> duckdb.DuckDBPyConnection:
        """Return the raw DuckDB connection for advanced use."""
        return self._conn

    def execute(self, sql: str, params: list[object] | None = None) -> duckdb.DuckDBPyConnection:
        """Execute a SQL statement, returning the connection cursor."""
        try:
            if params:
                return self._conn.execute(sql, params)
            return self._conn.execute(sql)
        except duckdb.Error as exc:
            raise DatabaseError(f"query failed: {exc}") from exc

    def executemany(self, sql: str, params_seq: list[list[object]]) -> None:
        """Execute a SQL statement with multiple parameter sets (batch insert)."""
        try:
            self._conn.executemany(sql, params_seq)
        except duckdb.Error as exc:
            raise DatabaseError(f"executemany failed: {exc}") from exc

    def close(self) -> None:
        """Close the underlying connection idempotently."""
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001 — best-effort cleanup
            pass
        logger.info("database closed: %s", self._path)
