"""Spreadsheet-safe export of attacker-/analyst-controlled cell values.

CSV quoting protects separators, not spreadsheet formulas. A leading apostrophe
forces dangerous string cells to text in mainstream spreadsheet software.
"""
from __future__ import annotations

PREFIX_TRIM = " \t\r\n\v\f\ufeff\u200b\u2060"
FORMULA_INITIAL = "=+-@"


def safe_spreadsheet_cell(value):
    if not isinstance(value, str):
        return value
    cleaned = value.lstrip(PREFIX_TRIM)
    if cleaned and cleaned[0] in FORMULA_INITIAL:
        return "'" + value
    # Prevent a tab/newline-only prefix being interpreted as multiple cells
    # by careless downstream tools; csv.writer still quotes delimiters.
    return value
