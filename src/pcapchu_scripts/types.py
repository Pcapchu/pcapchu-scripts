"""Core domain types — kept minimal and value-oriented (Go struct / Rust struct style)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class LogKind(Enum):
    """Known Zeek log categories.  Extend as needed."""

    CONN = auto()
    DNS = auto()
    HTTP = auto()
    SSL = auto()
    X509 = auto()
    FILES = auto()
    OCSP = auto()
    QUIC = auto()
    PACKET_FILTER = auto()
    PE = auto()
    DPDK = auto()
    NTP = auto()
    SMTP = auto()
    FTP = auto()
    SSH = auto()
    DHCP = auto()
    SMB = auto()
    DCE_RPC = auto()
    KERBEROS = auto()
    MYSQL = auto()
    RDPN = auto()
    SIP = auto()
    SNMP = auto()
    SOCKS = auto()
    TUNNEL = auto()
    WEIRD = auto()
    NOTICE = auto()
    SOFTWARE = auto()
    KNOWN_HOSTS = auto()
    KNOWN_SERVICES = auto()
    KNOWN_CERTS = auto()
    REPORTER = auto()
    CAPTURE_LOSS = auto()
    LOADED_SCRIPTS = auto()
    STATS = auto()
    UNKNOWN = auto()

    @classmethod
    def from_filename(cls, name: str) -> LogKind:
        """Map a log filename (e.g. ``conn.log``) to its enum variant."""
        stem = name.removesuffix(".log").upper().replace("-", "_")
        try:
            return cls[stem]
        except KeyError:
            return cls.UNKNOWN


@dataclass(frozen=True, slots=True)
class TableMeta:
    """Metadata for an ingested log table."""

    table_name: str
    source_file: str
    row_count: int
    column_count: int
    columns: list[ColumnMeta]
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ColumnMeta:
    """Schema information for a single column."""

    name: str
    dtype: str


@dataclass(frozen=True, slots=True)
class QueryResult:
    """Encapsulates a DuckDB query result in a serialisation-friendly shape."""

    columns: list[str]
    types: list[str]
    rows: list[list[Any]]
    row_count: int

    def as_dicts(self) -> list[dict[str, Any]]:
        """Return rows as a list of ``{column: value}`` dicts — handy for JSON."""
        return [dict(zip(self.columns, row, strict=True)) for row in self.rows]


@dataclass(frozen=True, slots=True)
class IngestReport:
    """Summary returned after a full ingestion run."""

    tables_created: int
    total_rows: int
    logs_deleted: list[str]
    errors: list[IngestError] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class IngestError:
    """A non-fatal error encountered during ingestion."""

    file: str
    message: str
