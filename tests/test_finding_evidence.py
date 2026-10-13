"""Tests for evidence attached to security findings."""

from datetime import UTC, datetime, timedelta

from logsentinel.detector import (
    detect_password_spraying,
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
)
from logsentinel.models import EventStatus, EventType, SecurityEvent

BASE_TIME = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)


def make_event(
    minute: int,
    username: str = "alice",
    event_type: EventType = EventType.LOGIN_FAILURE,
    status: EventStatus = EventStatus.FAILURE,
) -> SecurityEvent:
    """Create a security event for evidence tests."""
    return SecurityEvent(
        timestamp=BASE_TIME + timedelta(minutes=minute),
        source="server01",
        event_type=event_type,
        username=username,
        source_ip="192.168.1.50",
        status=status,
        message="Test security event",
    )


def test_det001_includes_matching_failed_login_evidence() -> None:
    """DET001 should identify the failed logins behind its finding."""
    events = [make_event(minute) for minute in range(5)]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    finding = findings[0]
    assert len(finding.evidence) == 5
    assert all("LOGIN_FAILURE" in item for item in finding.evidence)
    assert all("192.168.1.50" in item for item in finding.evidence)


def test_det002_includes_password_spraying_evidence() -> None:
    """DET002 should include events against distinct usernames."""
    events = [
        make_event(minute, username=f"user{index}")
        for index, minute in enumerate(range(5))
    ]

    findings = detect_password_spraying(events)

    assert len(findings) == 1
    finding = findings[0]
    assert len(finding.evidence) == 5
    assert all("LOGIN_FAILURE" in item for item in finding.evidence)
    assert {f"user{index}" in " ".join(finding.evidence) for index in range(5)} == {
        True
    }


def test_det003_includes_failures_and_success_evidence() -> None:
    """DET003 should include matching failures and the subsequent success."""
    events = [make_event(minute) for minute in (0, 1, 2)]
    events.append(
        make_event(
            3,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    findings = detect_success_after_failed_logins(events)

    assert len(findings) == 1
    finding = findings[0]
    assert len(finding.evidence) == 4
    assert sum("LOGIN_FAILURE" in item for item in finding.evidence) == 3
    assert sum("LOGIN_SUCCESS" in item for item in finding.evidence) == 1
    assert finding.evidence[-1].startswith(
        (BASE_TIME + timedelta(minutes=3)).isoformat()
    )
