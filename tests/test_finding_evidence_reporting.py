"""Tests for serializing detection evidence into investigation reports."""

from pathlib import Path

from logsentinel.reporting import generate_investigation_report


def test_report_includes_evidence_for_detected_findings() -> None:
    """Every generated finding should expose evidence as a JSON-ready list."""
    report = generate_investigation_report(Path("examples/sample_security.log"))

    assert report["findings"]

    for finding in report["findings"]:
        assert isinstance(finding["evidence"], list)
        assert finding["evidence"]
        assert all(isinstance(item, str) for item in finding["evidence"])

    det001 = next(
        finding for finding in report["findings"] if finding["rule_id"] == "DET001"
    )

    assert len(det001["evidence"]) == det001["attempt_count"]
