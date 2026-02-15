"""Log discovery and DuckDB ingestion.

Walks a directory tree, discovers ``*.log`` files produced by Zeek (JSON format),
and bulk-loads each into its own DuckDB table.  After successful import the
source log file is deleted so the AI agent never touches raw files.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import duckdb

from pcapchu_scripts.db import Database
from pcapchu_scripts.errors import DatabaseError
from pcapchu_scripts.errors import IngestError as IngestException
from pcapchu_scripts.types import IngestError, IngestReport

logger = logging.getLogger(__name__)

# Zeek JSON log header key — present in every well-formed Zeek JSON log line.
_ZEEK_TS_KEY = "ts"


def discover_logs(root: Path) -> list[Path]:
    """Recursively find all ``*.log`` files under *root*, sorted by name."""
    logs = sorted(root.rglob("*.log"))
    logger.info("discovered %d log file(s) under %s", len(logs), root)
    return logs


def _sanitize_table_name(log_path: Path) -> str:
    """Derive a DuckDB-safe table name from a log file path.

    ``conn.log``           → ``conn``
    ``packet_filter.log``  → ``packet_filter``
    """
    stem = log_path.stem
    # Replace characters that are not valid in an unquoted identifier.
    return stem.replace("-", "_").replace(".", "_").lower()


def _peek_columns(log_path: Path, sample_lines: int = 50) -> list[str]:
    """Read the first *sample_lines* JSON objects and return the union of keys.

    Zeek sometimes emits different keys across lines (e.g. optional fields).
    We collect all keys from the first N lines to build a comprehensive schema.
    """
    keys: dict[str, None] = {}  # ordered-set via dict
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, line in enumerate(fh):
            if idx >= sample_lines:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            for k in obj:
                keys[k] = None
    return list(keys)


def _ingest_single(db: Database, log_path: Path) -> int:
    """Import one Zeek JSON log into DuckDB.  Returns the row count."""
    table_name = _sanitize_table_name(log_path)
    abs_path = str(log_path.resolve())

    logger.info("ingesting %s → table '%s'", log_path, table_name)

    # Let DuckDB auto-detect the schema from the JSON lines file.
    # `read_json_auto` handles Zeek's newline-delimited JSON natively.
    try:
        db.execute(
            f"CREATE OR REPLACE TABLE \"{table_name}\" AS "  # noqa: S608
            f"SELECT * FROM read_json_auto('{abs_path}', "
            f"format='newline_delimited', "
            f"union_by_name=true, "
            f"maximum_object_size=104857600)"
        )
    except DatabaseError as exc:
        raise IngestException(str(log_path), str(exc)) from exc

    result = db.execute(f'SELECT COUNT(*) FROM "{table_name}"')  # noqa: S608
    row: tuple[int, ...] | None = result.fetchone()
    count: int = row[0] if row else 0

    logger.info("table '%s': %d rows ingested", table_name, count)
    return count


def ingest_all(
    db: Database,
    root: Path,
    *,
    delete_after: bool = True,
) -> IngestReport:
    """Discover, ingest, and optionally delete all Zeek JSON logs under *root*.

    Returns an :class:`IngestReport` summarising the operation.
    """
    logs = discover_logs(root)
    if not logs:
        logger.warning("no .log files found under %s", root)
        return IngestReport(tables_created=0, total_rows=0, logs_deleted=[])

    tables_created = 0
    total_rows = 0
    deleted: list[str] = []
    errors: list[IngestError] = []

    for log_path in logs:
        try:
            count = _ingest_single(db, log_path)
            tables_created += 1
            total_rows += count

            if delete_after:
                log_path.unlink()
                deleted.append(str(log_path))
                logger.info("deleted source log: %s", log_path)
        except IngestException as exc:
            logger.error("skipping %s: %s", log_path, exc)
            errors.append(IngestError(file=str(log_path), message=str(exc)))

    report = IngestReport(
        tables_created=tables_created,
        total_rows=total_rows,
        logs_deleted=deleted,
        errors=errors,
    )
    logger.info(
        "ingestion complete: %d tables, %d rows, %d errors",
        report.tables_created,
        report.total_rows,
        len(report.errors),
    )
    return report
