"""Log file ingestion utilities."""

from collections.abc import Iterator
from pathlib import Path


class LogIngestionError(Exception):
    """Raised when a log file cannot be ingested."""


def read_log_lines(file_path: Path) -> Iterator[str]:
    """Read a log file one line at a time."""
    try:
        with file_path.open("r", encoding="utf-8") as log_file:
            yield from log_file
    except (FileNotFoundError, IsADirectoryError, PermissionError) as exc:
        raise LogIngestionError(
            f"Unable to read log file: {file_path}"
        ) from exc
