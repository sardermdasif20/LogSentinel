"""Read security log files safely."""

from collections.abc import Iterator
from pathlib import Path


class LogIngestionError(Exception):
    """Raised when a security log file cannot be read."""


def read_log_lines(file_path: Path) -> Iterator[str]:
    """Yield lines from a UTF-8 encoded security log file."""
    try:
        with file_path.open("r", encoding="utf-8") as log_file:
            yield from log_file
    except (
        FileNotFoundError,
        IsADirectoryError,
        PermissionError,
        UnicodeDecodeError,
    ) as exc:
        raise LogIngestionError(f"Unable to read log file: {file_path}") from exc
