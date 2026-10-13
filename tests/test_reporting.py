"""Tests for security investigation report generation and export."""

import json
from pathlib import Path

import pytest

from logsentinel.ingestion import LogIngestionError
from logsentinel.reporting import (
    export_json_report,
    generate_investigation_report,
)


def test_report_contains_all_sample_events() -> None:
    """The sample dataset should be parsed into 16 events."""
    report = generate_investigation_report(Path("examples/sample_security.log"))

    assert report["summary"]["total_events"] == 16
    assert len(report["events"]) == 16
    assert report["parse_errors"] == []


def test_report_contains_expected_event_fields() -> None:
    """Serialized events should include fields and classified severity."""
    report = generate_investigation_report(Path("examples/sample_security.log"))

    event = report["events"][0]

    assert event["event_type"] == "LOGIN_SUCCESS"
    assert event["username"] == "alice"
    assert event["source_ip"] == "192.168.1.20"
    assert event["severity"] == "INFO"
    assert "timestamp" in event


def test_report_detects_repeated_failed_logins() -> None:
    """The sample log should trigger the repeated-login rule."""
    report = generate_investigation_report(Path("examples/sample_security.log"))

    rule_ids = {finding["rule_id"] for finding in report["findings"]}

    assert "DET001" in rule_ids


def test_report_has_summary_and_metadata() -> None:
    """The report should include metadata and analytics."""
    report = generate_investigation_report(Path("examples/sample_security.log"))

    assert report["report_version"] == "1.0"
    assert report["generated_at"]
    assert report["source_file"]
    assert report["summary"]["total_events"] == 16
    assert report["summary"]["total_findings"] == len(report["findings"])


def test_report_records_invalid_lines(tmp_path: Path) -> None:
    """Invalid log lines should be recorded with their line numbers."""
    log_file = tmp_path / "invalid.log"
    log_file.write_text(
        "this is not a valid log line\n",
        encoding="utf-8",
    )

    report = generate_investigation_report(log_file)

    assert report["summary"]["total_events"] == 0
    assert len(report["parse_errors"]) == 1
    assert report["parse_errors"][0]["line_number"] == 1


def test_empty_log_produces_empty_report(tmp_path: Path) -> None:
    """An empty file should produce an empty report without errors."""
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    report = generate_investigation_report(log_file)

    assert report["summary"]["total_events"] == 0
    assert report["summary"]["total_findings"] == 0
    assert report["events"] == []
    assert report["findings"] == []
    assert report["parse_errors"] == []


def test_json_export_can_be_loaded_again(tmp_path: Path) -> None:
    """Exported JSON should be readable and preserve report contents."""
    report = generate_investigation_report(Path("examples/sample_security.log"))
    output_file = tmp_path / "investigation_report.json"

    export_json_report(report, output_file)

    loaded_report = json.loads(output_file.read_text(encoding="utf-8"))

    assert loaded_report["report_version"] == "1.0"
    assert loaded_report["summary"]["total_events"] == 16
    assert loaded_report["events"] == report["events"]
    assert loaded_report["findings"] == report["findings"]


def test_missing_log_file_raises_error(tmp_path: Path) -> None:
    """A missing source file should raise the ingestion error."""
    missing_file = tmp_path / "missing.log"

    with pytest.raises(LogIngestionError):
        generate_investigation_report(missing_file)


def test_report_findings_include_structured_evidence() -> None:
    """Findings expose usernames and event types as structured fields."""
    report = generate_investigation_report(Path("examples/sample_security.log"))

    assert report["findings"]

    for finding in report["findings"]:
        assert isinstance(finding["affected_usernames"], list)
        assert isinstance(finding["event_types"], list)
        assert finding["event_types"]
        assert finding["evidence"]
