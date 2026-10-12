"""Tests for LogSentinel's repeated failed-login detection rule."""

from datetime import datetime, timedelta, timezone

import pytest

from logsentinel.detector import detect_repeated_failed_logins
from logsentinel.models import EventStatus, EventType, SecurityEvent


BASE_TIME = datetime(2026, 10, 12, 10, 0, tzinfo=timezone.utc)


def make_event(
    minute: int,
    source_ip: str = "192.168.1.50",
    event_type: EventType = EventType.LOGIN_FAILURE,
    status: EventStatus = EventStatus.FAILURE,
) -> SecurityEvent:
    """Create a security event for testing."""
    return SecurityEvent(
        timestamp=BASE_TIME + timedelta(minutes=minute),
        source="server01",
        event_type=event_type,
        username="alice",
        source_ip=source_ip,
        status=status,
        message="Test security event",
    )


def test_detects_repeated_failed_logins() -> None:
    """Detect five failed logins from one IP within ten minutes."""
    events = [make_event(minute) for minute in range(5)]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET001"
    assert findings[0]["rule_name"] == "Repeated Failed Logins"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["source_ip"] == "192.168.1.50"
    assert findings[0]["attempt_count"] == 5


def test_does_not_detect_below_threshold() -> None:
    """Do not flag fewer than five failed login attempts."""
    events = [make_event(minute) for minute in range(4)]

    assert detect_repeated_failed_logins(events) == []


def test_does_not_detect_attempts_outside_window() -> None:
    """Do not flag five attempts when fewer than five fit in the window."""
    events = [make_event(minute) for minute in (0, 11, 12, 13, 14)]

    assert detect_repeated_failed_logins(events) == []


def test_ignores_successful_logins() -> None:
    """Successful logins must not count as failed attempts."""
    events = [
        make_event(
            minute,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
        for minute in range(5)
    ]

    assert detect_repeated_failed_logins(events) == []


def test_groups_attempts_by_source_ip() -> None:
    """Failures from different IP addresses must not be combined."""
    events = [
        make_event(minute, source_ip="192.168.1.50")
        for minute in range(3)
    ]
    events.extend(
        make_event(minute, source_ip="192.168.1.60")
        for minute in range(3, 5)
    )

    assert detect_repeated_failed_logins(events) == []


def test_detects_attempts_at_window_boundary() -> None:
    """An attempt exactly ten minutes after the first remains in the window."""
    events = [
        make_event(minute)
        for minute in (0, 2, 4, 6, 10)
    ]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0]["attempt_count"] == 5


def test_empty_event_list_returns_no_findings() -> None:
    """An empty input must return no findings."""
    assert detect_repeated_failed_logins([]) == []


@pytest.mark.parametrize("threshold", [0, -1])
def test_rejects_invalid_threshold(threshold: int) -> None:
    """The threshold must be a positive integer."""
    with pytest.raises(ValueError, match="Threshold"):
        detect_repeated_failed_logins([], threshold=threshold)


@pytest.mark.parametrize("window_minutes", [0, -1])
def test_rejects_invalid_window(window_minutes: int) -> None:
    """The time window must be a positive number of minutes."""
    with pytest.raises(ValueError, match="Window"):
        detect_repeated_failed_logins(
            [],
            window_minutes=window_minutes,
        )
