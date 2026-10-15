"""Resolve real dataset CSV members inside ZIPs without path or identity ambiguity.

ZIP folder layout is not guaranteed: TON/UNSW currently have root CSVs while
CIC-IDS2017 uses MachineLearningCVE/*. Never infer a capture's independence
from a directory name, and never extract archive entries to find the input.
"""
from __future__ import annotations

import zipfile


def resolve_csv_member(archive: zipfile.ZipFile, basename: str) -> zipfile.ZipInfo:
    """Return the unique exact-basename CSV, at any nesting depth.

    Reject malicious paths, symlink entries, duplicate canonical paths, and
    multiple candidates. This is an identity guard, not license verification.
    """
    if (
        not basename.endswith(".csv")
        or "/" in basename
        or "\\" in basename
        or basename in {".", ".."}
    ):
        raise ValueError("Expected a single safe CSV basename")

    seen_paths: set[str] = set()
    matches: list[zipfile.ZipInfo] = []
    for item in archive.infolist():
        path = item.filename
        parts = path.rstrip("/").split("/")
        if (
            not path
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in parts)
            or path.startswith("~")
        ):
            raise ValueError("Unsafe ZIP member path")
        if item.is_dir():
            continue
        if (item.external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("ZIP symlink entry is not accepted")
        canonical = path.casefold()
        if canonical in seen_paths:
            raise ValueError("Duplicate ZIP member path")
        seen_paths.add(canonical)
        if parts[-1] == basename:
            matches.append(item)

    if not matches:
        raise FileNotFoundError("Required CSV member not found: " + basename)
    if len(matches) != 1:
        raise ValueError("Ambiguous CSV basename across ZIP subfolders: " + basename)
    return matches[0]
