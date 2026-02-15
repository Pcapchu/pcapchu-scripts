"""Zeek process launcher — runs Zeek against a pcap file to produce JSON logs."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Default Zeek scripts applied on every run.
_DEFAULT_SCRIPTS: list[str] = [
    "policy/tuning/json-logs",
    "frameworks/files/extract-all-files",
]


def _has_log_files(directory: Path) -> bool:
    """Check whether *directory* contains any ``.log`` files."""
    return any(directory.rglob("*.log"))


def run_zeek(
    pcap_path: Path,
    work_dir: Path,
    *,
    extra_scripts: list[str] | None = None,
    zeek_bin: str = "zeek",
    timeout_seconds: int = 600,
) -> bool:
    """Execute Zeek on *pcap_path*, writing outputs into *work_dir*.

    Returns ``True`` if usable log files were produced (even if Zeek itself
    reported errors).  Returns ``False`` only when Zeek failed **and** no
    ``.log`` files were generated.

    Raises:
        FileNotFoundError: If *pcap_path* does not exist.
    """
    if not pcap_path.is_file():
        raise FileNotFoundError(f"pcap file not found: {pcap_path}")

    work_dir.mkdir(parents=True, exist_ok=True)

    scripts = _DEFAULT_SCRIPTS + (extra_scripts or [])
    cmd: list[str] = [zeek_bin, "-C", "-r", str(pcap_path), *scripts]

    logger.info("running zeek: %s (cwd=%s)", " ".join(cmd), work_dir)

    result = subprocess.run(
        cmd,
        cwd=work_dir,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )

    has_logs = _has_log_files(work_dir)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if has_logs:
            logger.warning(
                "zeek exited with code %d but produced log files, continuing: %s",
                result.returncode,
                stderr,
            )
            return True
        logger.error("zeek failed and produced no log files: %s", stderr)
        return False

    logger.info("zeek completed successfully in %s", work_dir)
    return True
