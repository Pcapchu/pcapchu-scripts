"""Metadata catalogue — a ``_meta_tables`` table that describes every ingested log.

The AI agent queries this table first to understand what data is available,
then writes targeted SQL against the actual log tables.
"""

from __future__ import annotations

import logging

from pcapchu_scripts.db import Database
from pcapchu_scripts.errors import DatabaseError
from pcapchu_scripts.pkt2flow import FLOW_INDEX_TABLE
from pcapchu_scripts.types import ColumnMeta, TableMeta

logger = logging.getLogger(__name__)

_META_TABLE = "_meta_tables"

# Tables excluded from the public metadata catalogue.
_INTERNAL_TABLES: frozenset[str] = frozenset({_META_TABLE, FLOW_INDEX_TABLE})

_CREATE_META_DDL = f"""
CREATE TABLE IF NOT EXISTS "{_META_TABLE}" (
    table_name   VARCHAR NOT NULL PRIMARY KEY,
    source_file  VARCHAR NOT NULL,
    row_count    BIGINT  NOT NULL,
    column_count INTEGER NOT NULL,
    columns_json VARCHAR NOT NULL,
    size_bytes   BIGINT  NOT NULL
);
"""


def init_meta_table(db: Database) -> None:
    """Ensure the metadata catalogue table exists."""
    db.execute(_CREATE_META_DDL)
    logger.info("metadata table '%s' initialised", _META_TABLE)


def refresh_meta(db: Database) -> list[TableMeta]:
    """Re-scan all user tables and rebuild the metadata catalogue.

    For each table that is **not** the meta table itself we record:
    - table_name, source_file (= table_name + ".log")
    - row_count, column_count
    - columns as JSON array ``[{"name": ..., "dtype": ...}, ...]``
    - estimated storage size in bytes
    """
    import json as _json

    # Discover user tables (excluding internal tables).
    internal_list = ", ".join(f"'{t}'" for t in _INTERNAL_TABLES)
    rows = db.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = 'main' "
        f"AND table_name NOT IN ({internal_list})"
    ).fetchall()

    table_names: list[str] = [r[0] for r in rows]

    metas: list[TableMeta] = []

    # Truncate and rebuild.
    db.execute(f'DELETE FROM "{_META_TABLE}"')

    for tname in table_names:
        # Row count.
        rc_row = db.execute(f'SELECT COUNT(*) FROM "{tname}"').fetchone()  # noqa: S608
        row_count: int = rc_row[0] if rc_row else 0

        # Column info from DuckDB's pragma.
        col_rows = db.execute(f"PRAGMA table_info('{tname}')").fetchall()
        columns = [ColumnMeta(name=c[1], dtype=c[2]) for c in col_rows]
        column_count = len(columns)
        columns_json = _json.dumps([{"name": c.name, "dtype": c.dtype} for c in columns])

        # Estimated storage size (bytes) — DuckDB provides this via pragma.
        try:
            size_row = db.execute(
                f"SELECT estimated_size FROM duckdb_tables() WHERE table_name = '{tname}'"
            ).fetchone()
            size_bytes: int = size_row[0] if size_row else 0
        except DatabaseError:
            size_bytes = 0

        meta = TableMeta(
            table_name=tname,
            source_file=f"{tname}.log",
            row_count=row_count,
            column_count=column_count,
            columns=columns,
            size_bytes=size_bytes,
        )
        metas.append(meta)

        db.execute(
            f'INSERT INTO "{_META_TABLE}" '  # noqa: S608
            "(table_name, source_file, row_count, column_count, columns_json, size_bytes) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [tname, meta.source_file, row_count, column_count, columns_json, size_bytes],
        )

    logger.info("metadata refreshed: %d table(s) catalogued", len(metas))
    return metas
