"""Generate and export LogSentinel security investigation reports."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from logsentinel.analytics import build_analytics_report
from logsentinel.classifier import classify_event
from logsentinel.detector import (
    detect_password_spraying,
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
)
from logsentinel.ingestion import read_log_lines
from logsentinel.models import SecurityEvent, SecurityFinding
from logsentinel.parser import LogParserError, parse_log_line


def _serialize_event(event: SecurityEvent) -> dict[str, str]:
    """Convert a security event into JSON-compatible data."""
    return {
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type.value,
        "username": event.username,
        "source_ip": event.source_ip,
        "status": event.status.value,
        "message": event.message,
        "severity": classify_event(event).value,
    }


def _serialize_finding(
    finding: SecurityFinding,
) -> dict[str, Any]:
    """Convert a security finding into JSON-compatible data."""
    return {
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity.value,
        "source_ip": finding.source_ip,
        "attempt_count": finding.attempt_count,
        "window_minutes": finding.window_minutes,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "description": finding.description,
        "evidence": list(finding.evidence),
        "affected_usernames": list(finding.affected_usernames),
        "event_types": list(finding.event_types),
    }


def generate_investigation_report(
    log_path: Path,
    top_ip_limit: int = 5,
) -> dict[str, Any]:
    """Read a log file and build a complete investigation report."""
    if top_ip_limit < 1:
        raise ValueError("top_ip_limit must be at least 1")

    events: list[SecurityEvent] = []
    parse_errors: list[dict[str, str | int]] = []

    for line_number, line in enumerate(read_log_lines(log_path), start=1):
        if not line.strip():
            continue

        try:
            events.append(parse_log_line(line))
        except LogParserError as exc:
            parse_errors.append(
                {
                    "line_number": line_number,
                    "error": str(exc),
                    "raw_line": line.rstrip("\r\n"),
                }
            )

    findings = (
        detect_repeated_failed_logins(events)
        + detect_password_spraying(events)
        + detect_success_after_failed_logins(events)
    )

    analytics = build_analytics_report(
        events,
        findings,
        top_ip_limit=top_ip_limit,
    )

    return {
        "report_version": "1.0",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_file": str(log_path),
        "summary": analytics,
        "events": [_serialize_event(event) for event in events],
        "findings": [_serialize_finding(finding) for finding in findings],
        "parse_errors": parse_errors,
    }


def export_json_report(
    report: dict[str, Any],
    output_path: Path,
) -> None:
    """Write an investigation report to a JSON file."""
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
