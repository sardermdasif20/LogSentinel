"""Tests for LogSentinel log ingestion."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from logsentinel.ingestion import LogIngestionError, read_log_lines


def test_read_log_lines() -> None:
    """Verify that log lines are read correctly."""
    log_path = Path("examples/sample_security.log")

    lines = list(read_log_lines(log_path))

    assert len(lines) == 16
    assert lines[0].startswith("2026-10-03T08:12:04Z")
    assert lines[-1].startswith("2026-10-03T11:30:42Z")


def test_read_log_lines_returns_iterator() -> None:
    """Verify that log ingestion processes lines lazily."""
    log_path = Path("examples/sample_security.log")

    lines = read_log_lines(log_path)

    assert isinstance(lines, Iterator)


def test_missing_log_file_raises_ingestion_error() -> None:
    """Verify that a missing log file raises LogIngestionError."""
    log_path = Path("examples/does_not_exist.log")

    with pytest.raises(LogIngestionError, match="Unable to read log file"):
        list(read_log_lines(log_path))


def test_empty_log_file_returns_no_lines(tmp_path: Path) -> None:
    """Verify that an empty log file is handled normally."""
    log_path = tmp_path / "empty.log"
    log_path.touch()

    lines = list(read_log_lines(log_path))

    assert lines == []


def test_directory_path_raises_ingestion_error() -> None:
    """Verify that a directory cannot be ingested as a log file."""
    directory_path = Path("examples")

    with pytest.raises(LogIngestionError, match="Unable to read log file"):
        list(read_log_lines(directory_path))
