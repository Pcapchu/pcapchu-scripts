"""pkt2flow integration — splits a pcap into per-flow pcap files and indexes them in DuckDB.

pkt2flow produces per-flow pcap files organised by protocol (tcp_syn, udp, etc.).
This module runs the binary, walks the output directory, parses the structured
filenames, and builds a ``flow_index`` table in DuckDB that acts as a file-system
index.  The AI agent can then query flow metadata via SQL and retrieve specific
flow pcap paths for deeper analysis.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

from pcapchu_scripts.db import Database
from pcapchu_scripts.errors import DatabaseError

logger = logging.getLogger(__name__)

FLOW_INDEX_TABLE = "flow_index"

_DEFAULT_PKT2FLOW_BIN = "/home/linuxbrew/pkt2flow/build/pkt2flow"

_DEFAULT_OUTPUT_DIR_NAME = "output_flows"

_CREATE_FLOW_INDEX_DDL = f"""
CREATE TABLE IF NOT EXISTS "{FLOW_INDEX_TABLE}" (
    protocol  VARCHAR NOT NULL,
    src_ip    VARCHAR NOT NULL,
    src_port  INTEGER NOT NULL,
    dst_ip    VARCHAR NOT NULL,
    dst_port  INTEGER NOT NULL,
    ts_epoch  BIGINT  NOT NULL,
    file_path VARCHAR NOT NULL,
    file_size BIGINT  NOT NULL
);
"""


# ---------------------------------------------------------------------------
# pkt2flow execution
# ---------------------------------------------------------------------------


def run_pkt2flow(
    pcap_path: Path,
    output_dir: Path,
    *,
    pkt2flow_bin: str = _DEFAULT_PKT2FLOW_BIN,
    timeout_seconds: int = 600,
) -> bool:
    """Run pkt2flow on *pcap_path*, writing flow pcaps into *output_dir*.

    Returns ``True`` if the output directory contains flow pcap files.
    Returns ``False`` if pkt2flow failed **and** produced no output.
    Errors are logged, never raised.
    """
    if not pcap_path.is_file():
        logger.error("pcap file not found for pkt2flow: %s", pcap_path)
        return False

    pkt2flow = Path(pkt2flow_bin)
    if not pkt2flow.is_file():
        logger.warning("pkt2flow binary not found at %s — skipping flow split", pkt2flow_bin)
        return False

    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [str(pkt2flow), "-u", "-v", "-x", "-o", str(output_dir), str(pcap_path)]
    logger.info("running pkt2flow: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("pkt2flow timed out after %d seconds", timeout_seconds)
        return False

    has_files = any(output_dir.rglob("*.pcap"))

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if has_files:
            logger.warning(
                "pkt2flow exited with code %d but produced flow files, continuing: %s",
                result.returncode,
                stderr,
            )
            return True
        logger.error("pkt2flow failed and produced no flow files: %s", stderr)
        return False

    logger.info("pkt2flow completed successfully, output in %s", output_dir)
    return True


# ---------------------------------------------------------------------------
# Filename parsing
# ---------------------------------------------------------------------------


def _parse_flow_filename(filename: str) -> tuple[str, int, str, int, int] | None:
    """Parse a pkt2flow filename into ``(src_ip, src_port, dst_ip, dst_port, ts_epoch)``.

    Expected format: ``srcIP_srcPort_dstIP_dstPort_timestamp.pcap``

    Both IPv4 and IPv6 addresses are supported — neither contains underscores,
    so splitting on ``_`` always yields exactly five fields.
    """
    stem = filename.removesuffix(".pcap")
    if not stem or stem == filename:
        return None

    parts = stem.split("_")
    if len(parts) != 5:
        return None

    src_ip, src_port_s, dst_ip, dst_port_s, ts_s = parts

    try:
        src_port = int(src_port_s)
        dst_port = int(dst_port_s)
        ts_epoch = int(ts_s)
    except ValueError:
        return None

    return src_ip, src_port, dst_ip, dst_port, ts_epoch


# ---------------------------------------------------------------------------
# Flow indexing
# ---------------------------------------------------------------------------


def index_flows(db: Database, output_dir: Path) -> int:
    """Walk *output_dir*, parse flow filenames, and insert into ``flow_index``.

    Returns the number of flows indexed.
    """
    db.execute(_CREATE_FLOW_INDEX_DDL)

    # Clear previous entries (idempotent re-run).
    db.execute(f'DELETE FROM "{FLOW_INDEX_TABLE}"')

    entries: list[list[object]] = []

    for root, _dirs, files in os.walk(output_dir):
        protocol = Path(root).name
        # Skip the top-level output_flows directory itself.
        if Path(root) == output_dir:
            continue

        for fname in files:
            if not fname.endswith(".pcap"):
                continue

            parsed = _parse_flow_filename(fname)
            if parsed is None:
                logger.warning("skipping unparseable flow filename: %s", fname)
                continue

            src_ip, src_port, dst_ip, dst_port, ts_epoch = parsed
            file_path = os.path.join(root, fname)
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                file_size = 0

            entries.append([
                protocol, src_ip, src_port, dst_ip, dst_port, ts_epoch, file_path, file_size,
            ])

    if entries:
        try:
            db.executemany(
                f'INSERT INTO "{FLOW_INDEX_TABLE}" VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                entries,
            )
        except DatabaseError as exc:
            logger.error("failed to insert flow index entries: %s", exc)
            return 0

    logger.info("flow_index: %d flow(s) indexed from %s", len(entries), output_dir)
    return len(entries)
