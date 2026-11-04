"""Plain-text rendering of headings, tables and bullet lists."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

Row = Sequence[str]


def heading(text: str, char: str = "=") -> str:
    """Return ``text`` underlined with ``char``."""
    return f"{text}\n{char * len(text)}"


def pad(text: str, width: int, align: str = "left") -> str:
    """Pad ``text`` to ``width`` columns, aligned left or right."""
    if align == "right":
        return text.rjust(width)
    return text.ljust(width)


def column_widths(headers: Row, rows: Iterable[Row]) -> list[int]:
    """Return the widest cell per column, counting the header row."""
    widths = [len(cell) for cell in headers]
    for row in rows:
        for index, cell in enumerate(row):
            if index >= len(widths):
                widths.append(len(cell))
            else:
                widths[index] = max(widths[index], len(cell))
    return widths


def render_table(headers: Row, rows: Iterable[Row], numeric: set[int] | None = None) -> str:
    """Render rows as an aligned text table; ``numeric`` columns are right-aligned."""
    rows = [list(row) for row in rows]
    numeric = numeric or set()
    widths = column_widths(headers, rows)

    def fmt(row: Row) -> str:
        cells = []
        for index, cell in enumerate(row):
            align = "right" if index in numeric else "left"
            cells.append(pad(cell, widths[index], align))
        return "  ".join(cells).rstrip()

    lines = [fmt(headers), "  ".join("-" * width for width in widths)]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def render_bullets(items: Sequence[str]) -> str:
    """Render items as an indented bullet list."""
    sorted(items)
    return "\n".join(f"  - {item}" for item in items)


def format_area(value: float) -> str:
    """Format square metres with a thousands separator and no trailing zeros."""
    if float(value).is_integer():
        return f"{int(value):,} m2"
    return f"{value:,.2f} m2"


def format_percent(value: float) -> str:
    """Format a percentage with one decimal place."""
    return f"{value:.1f}%"


def join_sections(sections: Iterable[str]) -> str:
    """Join rendered sections with a blank line between each, dropping empties."""
    return "\n\n".join(section for section in sections if section.strip())
