"""Tests for the LogSentinel command-line interface."""

import json
from pathlib import Path

import pytest

from logsentinel.main import main


def test_cli_generates_report(monkeypatch, tmp_path: Path, capsys) -> None:
    output_file = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", [
        "logsentinel", "--input", "examples/sample_security.log",
        "--output", str(output_file),
    ])

    exit_code = main()
    captured = capsys.readouterr()
    report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["summary"]["total_events"] == 16
    assert report["summary"]["total_findings"] == 1
    assert "Events analyzed:  16" in captured.out
    assert "DET001" in captured.out
    assert "Report generated successfully." in captured.out


def test_cli_missing_input_returns_error(monkeypatch, tmp_path: Path, capsys) -> None:
    missing_file = tmp_path / "missing.log"
    output_file = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", [
        "logsentinel", "--input", str(missing_file),
        "--output", str(output_file),
    ])

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "LogSentinel error:" in captured.err
    assert not output_file.exists()


def test_cli_reports_parse_errors(monkeypatch, tmp_path: Path, capsys) -> None:
    input_file = tmp_path / "malformed.log"
    output_file = tmp_path / "report.json"
    input_file.write_text("not a valid security event\n", encoding="utf-8")
    monkeypatch.setattr("sys.argv", [
        "logsentinel", "--input", str(input_file),
        "--output", str(output_file),
    ])

    exit_code = main()
    captured = capsys.readouterr()
    report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert report["summary"]["total_events"] == 0
    assert len(report["parse_errors"]) == 1
    assert "Malformed log lines:" in captured.out
    assert "Line 1:" in captured.out


def test_cli_json_format_prints_valid_json(monkeypatch, tmp_path: Path, capsys) -> None:
    output_file = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", [
        "logsentinel", "--input", "examples/sample_security.log",
        "--output", str(output_file), "--format", "json",
    ])

    exit_code = main()
    captured = capsys.readouterr()
    terminal_report = json.loads(captured.out)
    saved_report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert terminal_report["summary"]["total_events"] == 16
    assert terminal_report["summary"]["total_findings"] == 1
    assert terminal_report["findings"][0]["rule_id"] == "DET001"
    assert saved_report["summary"]["total_events"] == 16


def test_cli_top_ips_limits_analytics(monkeypatch, tmp_path: Path, capsys) -> None:
    output_file = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", [
        "logsentinel", "--input", "examples/sample_security.log",
        "--output", str(output_file), "--format", "json",
        "--top-ips", "2",
    ])

    exit_code = main()
    report = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(report["summary"]["top_source_ips"]) == 2
    assert report["summary"]["top_source_ips"][0]["source_ip"] == "192.168.1.50"


def test_cli_rejects_invalid_top_ips(monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["logsentinel", "--top-ips", "0"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert "--top-ips must be at least 1" in captured.err


def test_cli_fail_on_findings_returns_two(monkeypatch, tmp_path: Path, capsys) -> None:
    output_file = tmp_path / "report.json"
    monkeypatch.setattr("sys.argv", [
        "logsentinel", "--input", "examples/sample_security.log",
        "--output", str(output_file), "--fail-on-findings",
    ])

    exit_code = main()
    captured = capsys.readouterr()
    report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 2
    assert report["summary"]["total_findings"] == 1
    assert "DET001" in captured.out
    assert output_file.exists()
