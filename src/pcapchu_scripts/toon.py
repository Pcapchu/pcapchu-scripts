"""Lightweight TOON (Token-Oriented Object Notation) encoder for metadata.

TOON uses YAML-like indentation for objects and CSV-style tabular rows for
uniform arrays.  Only the subset needed for ``TableMeta`` / ``ColumnMeta``
is implemented here — no general-purpose parser.

Specification: https://github.com/toon-format/toon
"""

from __future__ import annotations

from pcapchu_scripts.types import TableMeta


def _escape(value: str) -> str:
    """Quote a string value only when it contains structural characters."""
    if not value:
        return '""'
    needs_quote = any(ch in value for ch in (",", "\n", '"', " "))
    if needs_quote:
        escaped = value.replace('"', '""')
        return f'"{escaped}"'
    return value


def meta_to_toon(metas: list[TableMeta]) -> str:
    """Encode a list of :class:`TableMeta` into TOON format.

    Layout::

        tables[N]{table_name,source_file,row_count,column_count,size_bytes}:
          conn,conn.log,1234,12,8192
          dns,dns.log,500,8,4096

        conn[12]{name,dtype}:
          ts,DOUBLE
          uid,VARCHAR

        dns[8]{name,dtype}:
          ...
    """
    if not metas:
        return "tables[0]{table_name,source_file,row_count,column_count,size_bytes}:\n"

    lines: list[str] = []

    # --- summary table --------------------------------------------------------
    fields = "table_name,source_file,row_count,column_count,size_bytes"
    lines.append(f"tables[{len(metas)}]{{{fields}}}:")
    for m in metas:
        row = ",".join([
            _escape(m.table_name),
            _escape(m.source_file),
            str(m.row_count),
            str(m.column_count),
            str(m.size_bytes),
        ])
        lines.append(f"  {row}")

    # --- per-table column schemas ---------------------------------------------
    for m in metas:
        if not m.columns:
            continue
        lines.append("")
        lines.append(f"{_escape(m.table_name)}[{len(m.columns)}]{{name,dtype}}:")
        for col in m.columns:
            lines.append(f"  {_escape(col.name)},{_escape(col.dtype)}")

    lines.append("")  # trailing newline
    return "\n".join(lines)
