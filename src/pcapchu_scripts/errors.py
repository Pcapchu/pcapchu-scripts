"""Custom exception hierarchy — explicit error types like Go sentinel errors."""

from __future__ import annotations


class PcapchuScriptsError(Exception):
    """Base error for all pcapchu-scripts operations."""


class ZeekError(PcapchuScriptsError):
    """Raised when the Zeek subprocess fails."""

    def __init__(self, return_code: int, stderr: str) -> None:
        self.return_code = return_code
        self.stderr = stderr
        super().__init__(f"zeek exited with code {return_code}: {stderr}")


class DatabaseError(PcapchuScriptsError):
    """Raised on DuckDB operational failures."""


class IngestError(PcapchuScriptsError):
    """Raised when a log file cannot be ingested."""

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"failed to ingest {path}: {reason}")


class QueryError(PcapchuScriptsError):
    """Raised when a user-supplied SQL query is invalid or fails."""
