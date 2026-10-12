"""Tests for the LogSentinel command-line interface."""

import json
from pathlib import Path

from logsentinel.main import main


def test_cli_generates_report(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    """The CLI should export a report and print its summary."""
    output_file = tmp_path / "report.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentinel",
            "--input",
            "examples/sample_security.log",
            "--output",
            str(output_file),
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()
    report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["summary"]["total_events"] == 16
    assert report["summary"]["total_findings"] == 1
    assert "Events analyzed:  16" in captured.out
    assert "DET001" in captured.out
    assert "Report generated successfully." in captured.out


def test_cli_missing_input_returns_error(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    """The CLI should return an error for a missing input file."""
    missing_file = tmp_path / "missing.log"
    output_file = tmp_path / "report.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentinel",
            "--input",
            str(missing_file),
            "--output",
            str(output_file),
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "LogSentinel error:" in captured.err
    assert not output_file.exists()


def test_cli_reports_parse_errors(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    """The CLI should report malformed lines without crashing."""
    input_file = tmp_path / "malformed.log"
    output_file = tmp_path / "report.json"
    input_file.write_text(
        "not a valid security event\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "logsentinel",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()
    report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["summary"]["total_events"] == 0
    assert len(report["parse_errors"]) == 1
    assert "Malformed log lines:" in captured.out
    assert "Line 1:" in captured.out
