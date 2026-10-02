"""Tests for LogSentinel security event models."""

from datetime import datetime, timezone

import pytest

from logsentinel.models import EventStatus, EventType, SecurityEvent


def test_event_types() -> None:
    """Verify all supported event types exist."""
    assert {event_type.value for event_type in EventType} == {
        "LOGIN_SUCCESS",
        "LOGIN_FAILURE",
        "ACCOUNT_LOCK",
        "PASSWORD_CHANGE",
        "PRIVILEGE_CHANGE",
        "FILE_ACCESS",
        "CONNECTION",
    }


def test_event_statuses() -> None:
    """Verify all supported event statuses exist."""
    assert {status.value for status in EventStatus} == {
        "SUCCESS",
        "FAILURE",
        "INFO",
        "WARNING",
    }


def test_security_event_creation() -> None:
    """Verify a SecurityEvent can be created with valid values."""
    timestamp = datetime(2026, 10, 3, 8, 14, 22, tzinfo=timezone.utc)

    event = SecurityEvent(
        timestamp=timestamp,
        source="server01",
        event_type=EventType.LOGIN_FAILURE,
        username="alice",
        source_ip="192.168.1.50",
        status=EventStatus.FAILURE,
        message="Invalid password",
    )

    assert event.timestamp == timestamp
    assert event.source == "server01"
    assert event.event_type is EventType.LOGIN_FAILURE
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.50"
    assert event.status is EventStatus.FAILURE
    assert event.message == "Invalid password"


def test_security_event_is_immutable() -> None:
    """Verify SecurityEvent fields cannot be modified after creation."""
    event = SecurityEvent(
        timestamp=datetime(2026, 10, 3, 8, 14, 22, tzinfo=timezone.utc),
        source="server01",
        event_type=EventType.LOGIN_FAILURE,
        username="alice",
        source_ip="192.168.1.50",
        status=EventStatus.FAILURE,
        message="Invalid password",
    )

    with pytest.raises(AttributeError):
        event.username = "bob"