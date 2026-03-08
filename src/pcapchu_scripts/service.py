"""Top-level orchestrator — ties zeek → ingest → metadata together.

This module is the single entry-point for the full initialisation pipeline.
"""

from __future__ import annotations

import dataclasses
import json
import logging
from pathlib import Path
from typing import Any

from pcapchu_scripts.db import Database
from pcapchu_scripts.ingest import ingest_all
from pcapchu_scripts.metadata import init_meta_table, refresh_meta
from pcapchu_scripts.pkt2flow import (
    _DEFAULT_OUTPUT_DIR_NAME,
    _DEFAULT_PKT2FLOW_BIN,
    index_flows,
    run_pkt2flow,
)
from pcapchu_scripts.query import query as run_query
from pcapchu_scripts.toon import meta_to_toon
from pcapchu_scripts.types import IngestReport, QueryResult, TableMeta
from pcapchu_scripts.zeek import run_zeek

logger = logging.getLogger(__name__)


class PcapchuScripts:
    """Façade that manages the full lifecycle.

    Typical usage::

        with PcapchuScripts(work_dir="/data", db_path="/data/pcapchu-scripts.duckdb") as p:
            p.init("/data/capture.pcap")
            result = p.query("SELECT * FROM conn LIMIT 10")
    """

    __slots__ = ("_db", "_db_path", "_pkt2flow_bin", "_work_dir")

    def __init__(
        self,
        work_dir: str | Path,
        db_path: str | Path | None = None,
        *,
        pkt2flow_bin: str = _DEFAULT_PKT2FLOW_BIN,
    ) -> None:
        self._work_dir = Path(work_dir)
        self._db_path = Path(db_path) if db_path else self._work_dir / "pcapchu-scripts.duckdb"
        self._pkt2flow_bin = pkt2flow_bin
        self._db = Database(self._db_path)
        init_meta_table(self._db)

    # -- context manager -------------------------------------------------------

    def __enter__(self) -> PcapchuScripts:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- public API ------------------------------------------------------------

    def init(
        self,
        pcap_path: str | Path,
        *,
        run_zeek_first: bool = True,
        extra_scripts: list[str] | None = None,
        delete_logs: bool = True,
        run_pkt2flow_step: bool = True,
    ) -> IngestReport:
        """Run the full initialisation pipeline.

        1. (Optional) Execute Zeek on *pcap_path*.
        2. Walk *work_dir* and ingest all ``.log`` files into DuckDB.
        3. (Optional) Run pkt2flow to split pcap into per-flow files and index them.
        4. Rebuild the metadata catalogue.
        5. Delete source ``.log`` files.

        Returns:
            An :class:`IngestReport` summarising what was done.
        """
        pcap = Path(pcap_path)

        if run_zeek_first:
            has_logs = run_zeek(pcap, self._work_dir, extra_scripts=extra_scripts)
            if not has_logs:
                logger.error("zeek produced no log files — nothing to ingest")
                return IngestReport(tables_created=0, total_rows=0, logs_deleted=[])

        report = ingest_all(self._db, self._work_dir, delete_after=delete_logs)

        # --- pkt2flow: split pcap into per-flow files and build flow_index ---
        if run_pkt2flow_step:
            flows_dir = self._work_dir / _DEFAULT_OUTPUT_DIR_NAME
            ok = run_pkt2flow(
                pcap, flows_dir, pkt2flow_bin=self._pkt2flow_bin,
            )
            if ok:
                n = index_flows(self._db, flows_dir)
                logger.info("pkt2flow: indexed %d flow(s)", n)
            else:
                logger.warning("pkt2flow step skipped or failed — no flow index created")

        refresh_meta(self._db)
        return report

    def ingest_only(self, *, delete_logs: bool = True) -> IngestReport:
        """Ingest already-existing Zeek logs (skip the Zeek step)."""
        report = ingest_all(self._db, self._work_dir, delete_after=delete_logs)
        refresh_meta(self._db)
        return report

    def query(self, sql: str, *, max_rows: int = 50_000) -> QueryResult:
        """Execute a SQL query and return structured results."""
        return run_query(self._db, sql, max_rows=max_rows)

    def query_json(self, sql: str, *, max_rows: int = 50_000) -> str:
        """Execute a SQL query and return the result as a JSON string."""
        result = self.query(sql, max_rows=max_rows)
        return json.dumps(dataclasses.asdict(result), default=_json_default, ensure_ascii=False)

    def get_meta(self) -> list[TableMeta]:
        """Return the current metadata catalogue (re-scanned)."""
        return refresh_meta(self._db)

    def get_meta_json(self) -> str:
        """Return metadata as a JSON string."""
        metas = self.get_meta()
        return json.dumps(
            [dataclasses.asdict(m) for m in metas], default=_json_default, ensure_ascii=False
        )

    def get_meta_toon(self) -> str:
        """Return metadata as a TOON string (token-efficient for LLM agents)."""
        return meta_to_toon(self.get_meta())

    def close(self) -> None:
        """Close the database connection."""
        self._db.close()


def _json_default(obj: Any) -> Any:  # noqa: ANN401
    """Fallback serialiser for types that ``json.dumps`` cannot handle natively."""
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)
