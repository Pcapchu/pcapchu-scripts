"""CLI entry-point for pcapchu-scripts.

Subcommands:
    init   — Run Zeek + ingest logs into DuckDB.
    ingest — Ingest existing Zeek logs (no Zeek run).
    query  — Execute a SQL statement interactively.
    meta   — Print the metadata catalogue.
    serve  — Start a lightweight JSON-RPC server (stdin/stdout) for AI agents.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from pcapchu_scripts.service import PcapchuScripts


def _configure_logging(verbose: bool) -> None:  # noqa: FBT001
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )


def _cmd_init(args: argparse.Namespace) -> int:
    with PcapchuScripts(work_dir=args.work_dir, db_path=args.db) as p:
        report = p.init(
            args.pcap,
            run_zeek_first=not args.no_zeek,
            delete_logs=not args.keep_logs,
            run_pkt2flow_step=not args.no_pkt2flow,
        )
        print(json.dumps({
            "tables_created": report.tables_created,
            "total_rows": report.total_rows,
            "logs_deleted": report.logs_deleted,
            "errors": [{"file": e.file, "message": e.message} for e in report.errors],
        }, indent=2, ensure_ascii=False))
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    with PcapchuScripts(work_dir=args.work_dir, db_path=args.db) as p:
        report = p.ingest_only(delete_logs=not args.keep_logs)
        print(json.dumps({
            "tables_created": report.tables_created,
            "total_rows": report.total_rows,
            "logs_deleted": report.logs_deleted,
            "errors": [{"file": e.file, "message": e.message} for e in report.errors],
        }, indent=2, ensure_ascii=False))
    return 0


def _cmd_query(args: argparse.Namespace) -> int:
    with PcapchuScripts(work_dir=args.work_dir, db_path=args.db) as p:
        print(p.query_json(args.sql, max_rows=args.limit))
    return 0


def _cmd_meta(args: argparse.Namespace) -> int:
    with PcapchuScripts(work_dir=args.work_dir, db_path=args.db) as p:
        print(p.get_meta_json())
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Minimal stdin/stdout JSON-RPC loop for AI agent integration.

    Protocol (one JSON object per line):

        → {"method": "query",  "params": {"sql": "SELECT ..."}}
        ← {"result": {...}}

        → {"method": "meta"}
        ← {"result": [...]}
    """
    p = PcapchuScripts(work_dir=args.work_dir, db_path=args.db)
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                _write_response({"error": f"invalid JSON: {exc}"})
                continue

            method = req.get("method", "")
            params = req.get("params", {})

            if method == "query":
                sql = params.get("sql", "")
                if not sql:
                    _write_response({"error": "missing 'sql' in params"})
                    continue
                max_rows = params.get("max_rows", 50_000)
                try:
                    result = p.query_json(sql, max_rows=max_rows)
                    _write_response({"result": json.loads(result)})
                except Exception as exc:
                    _write_response({"error": str(exc)})

            elif method == "meta":
                try:
                    meta = p.get_meta_json()
                    _write_response({"result": json.loads(meta)})
                except Exception as exc:
                    _write_response({"error": str(exc)})

            elif method == "ingest":
                try:
                    report = p.ingest_only(delete_logs=params.get("delete_logs", True))
                    _write_response({"result": {
                        "tables_created": report.tables_created,
                        "total_rows": report.total_rows,
                        "logs_deleted": report.logs_deleted,
                    }})
                except Exception as exc:
                    _write_response({"error": str(exc)})

            else:
                _write_response({"error": f"unknown method: {method}"})
    except KeyboardInterrupt:
        pass
    finally:
        p.close()
    return 0


def _write_response(obj: object) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
    sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="pcapchu-scripts",
        description="Zeek log → DuckDB ingestion & query layer for AI-driven pcap analysis.",
    )
    parser.add_argument(
        "-w", "--work-dir",
        type=Path,
        default=Path.cwd(),
        help="Working directory for Zeek output and log discovery (default: cwd).",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help="Path to DuckDB database file (default: <work-dir>/pcapchu-scripts.duckdb).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")

    sub = parser.add_subparsers(dest="command", required=True)

    # -- init ------------------------------------------------------------------
    p_init = sub.add_parser("init", help="Run Zeek on a pcap file and ingest logs.")
    p_init.add_argument("pcap", type=Path, help="Path to the pcap/pcapng file.")
    p_init.add_argument("--no-zeek", action="store_true", help="Skip the Zeek run.")
    p_init.add_argument("--no-pkt2flow", action="store_true", help="Skip the pkt2flow flow-split step.")
    p_init.add_argument("--keep-logs", action="store_true", help="Do not delete log files.")
    p_init.set_defaults(func=_cmd_init)

    # -- ingest ----------------------------------------------------------------
    p_ingest = sub.add_parser("ingest", help="Ingest existing Zeek logs (no Zeek run).")
    p_ingest.add_argument("--keep-logs", action="store_true", help="Do not delete log files.")
    p_ingest.set_defaults(func=_cmd_ingest)

    # -- query -----------------------------------------------------------------
    p_query = sub.add_parser("query", help="Execute a SQL query.")
    p_query.add_argument("sql", help="SQL statement to execute.")
    p_query.add_argument("--limit", type=int, default=50_000, help="Max rows to return.")
    p_query.set_defaults(func=_cmd_query)

    # -- meta ------------------------------------------------------------------
    p_meta = sub.add_parser("meta", help="Print the metadata catalogue as JSON.")
    p_meta.set_defaults(func=_cmd_meta)

    # -- serve -----------------------------------------------------------------
    p_serve = sub.add_parser("serve", help="Start stdin/stdout JSON-RPC server for AI agents.")
    p_serve.set_defaults(func=_cmd_serve)

    args = parser.parse_args()
    _configure_logging(args.verbose)

    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
