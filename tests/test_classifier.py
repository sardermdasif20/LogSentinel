"""Tests for LogSentinel event severity classification."""

from datetime import UTC, datetime

import pytest

from logsentinel.classifier import classify_event
from logsentinel.models import (
    EventStatus,
    EventType,
    SecurityEvent,
    Severity,
)


@pytest.mark.parametrize(
    ("event_type", "expected_severity"),
    [
        (EventType.LOGIN_SUCCESS, Severity.INFO),
        (EventType.LOGIN_FAILURE, Severity.WARNING),
        (EventType.ACCOUNT_LOCK, Severity.HIGH),
        (EventType.PASSWORD_CHANGE, Severity.INFO),
        (EventType.PRIVILEGE_CHANGE, Severity.HIGH),
        (EventType.FILE_ACCESS, Severity.INFO),
        (EventType.CONNECTION, Severity.INFO),
    ],
)
def test_classify_event_returns_expected_severity(
    event_type: EventType,
    expected_severity: Severity,
) -> None:
    """Verify each supported event type receives its default severity."""
    event = SecurityEvent(
        timestamp=datetime(2026, 10, 3, 8, 14, 22, tzinfo=UTC),
        source="server01",
        event_type=event_type,
        username="alice",
        source_ip="192.168.1.50",
        status=EventStatus.INFO,
        message="Sample security event",
    )

    assert classify_event(event) is expected_severity


def test_classify_event_returns_severity_enum() -> None:
    """Verify classification returns a Severity enum member."""
    event = SecurityEvent(
        timestamp=datetime(2026, 10, 3, 8, 14, 22, tzinfo=UTC),
        source="server01",
        event_type=EventType.LOGIN_FAILURE,
        username="alice",
        source_ip="192.168.1.50",
        status=EventStatus.FAILURE,
        message="Invalid password",
    )

    result = classify_event(event)

    assert isinstance(result, Severity)


def test_severity_levels() -> None:
    """Verify all supported severity levels exist."""
    assert {severity.value for severity in Severity} == {
        "INFO",
        "WARNING",
        "HIGH",
        "CRITICAL",
    }
