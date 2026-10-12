"""Tests for LogSentinel's detection rules."""

from datetime import UTC, datetime, timedelta

import pytest

from logsentinel.detector import (
    detect_password_spraying,
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
)
from logsentinel.models import (
    EventStatus,
    EventType,
    SecurityEvent,
    SecurityFinding,
    Severity,
)

BASE_TIME = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)


def make_event(
    minute: int,
    source_ip: str = "192.168.1.50",
    username: str = "alice",
    event_type: EventType = EventType.LOGIN_FAILURE,
    status: EventStatus = EventStatus.FAILURE,
) -> SecurityEvent:
    """Create a security event for testing."""
    return SecurityEvent(
        timestamp=BASE_TIME + timedelta(minutes=minute),
        source="server01",
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        status=status,
        message="Test security event",
    )


def test_detects_repeated_failed_logins() -> None:
    """Detect five failed logins from one IP within ten minutes."""
    events = [make_event(minute) for minute in range(5)]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, SecurityFinding)
    assert finding.rule_id == "DET001"
    assert finding.rule_name == "Repeated Failed Logins"
    assert finding.severity is Severity.HIGH
    assert finding.source_ip == "192.168.1.50"
    assert finding.attempt_count == 5
    assert finding.window_minutes == 10
    assert finding.first_seen == BASE_TIME
    assert finding.last_seen == BASE_TIME + timedelta(minutes=4)
    assert "5 failed login attempts" in finding.description


def test_repeated_failed_logins_returns_one_finding_per_ip() -> None:
    """Return only one finding per IP even when failures continue."""
    events = [make_event(minute) for minute in range(8)]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].source_ip == "192.168.1.50"


def test_does_not_detect_below_threshold() -> None:
    """Do not flag fewer than five failed login attempts."""
    events = [make_event(minute) for minute in range(4)]

    assert detect_repeated_failed_logins(events) == []


def test_does_not_detect_attempts_outside_window() -> None:
    """Do not flag attempts when fewer than five fit in the window."""
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
    events = [make_event(minute, source_ip="192.168.1.50") for minute in range(3)]
    events.extend(
        make_event(minute, source_ip="192.168.1.60") for minute in range(3, 5)
    )

    assert detect_repeated_failed_logins(events) == []


def test_detects_attempts_at_window_boundary() -> None:
    """An attempt exactly ten minutes after the first remains in the window."""
    events = [make_event(minute) for minute in (0, 2, 4, 6, 10)]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].attempt_count == 5


def test_empty_event_list_returns_no_findings() -> None:
    """An empty input must return no findings."""
    assert detect_repeated_failed_logins([]) == []


@pytest.mark.parametrize("threshold", [0, -1])
def test_rejects_invalid_threshold(threshold: int) -> None:
    """The repeated-login threshold must be positive."""
    with pytest.raises(ValueError, match="Threshold"):
        detect_repeated_failed_logins([], threshold=threshold)


@pytest.mark.parametrize("window_minutes", [0, -1])
def test_rejects_invalid_window(window_minutes: int) -> None:
    """The repeated-login time window must be positive."""
    with pytest.raises(ValueError, match="Window"):
        detect_repeated_failed_logins(
            [],
            window_minutes=window_minutes,
        )


def test_detects_password_spraying() -> None:
    """Detect failures against five distinct usernames from one IP."""
    events = [
        make_event(minute, username=f"user{index}")
        for index, minute in enumerate(range(5))
    ]

    findings = detect_password_spraying(events)

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, SecurityFinding)
    assert finding.rule_id == "DET002"
    assert finding.rule_name == "Possible Password Spraying"
    assert finding.severity is Severity.HIGH
    assert finding.source_ip == "192.168.1.50"
    assert finding.attempt_count == 5
    assert finding.window_minutes == 10
    assert finding.first_seen == BASE_TIME
    assert finding.last_seen == BASE_TIME + timedelta(minutes=4)
    assert "5 distinct usernames" in finding.description


def test_password_spraying_ignores_missing_usernames() -> None:
    """Events without usernames must not count toward password spraying."""
    events = [make_event(minute, username=None) for minute in range(5)]

    assert detect_password_spraying(events) == []


def test_password_spraying_requires_distinct_username_threshold() -> None:
    """Four distinct usernames must not meet the default threshold."""
    events = [
        make_event(minute, username=f"user{index}")
        for index, minute in enumerate(range(4))
    ]

    assert detect_password_spraying(events) == []


def test_password_spraying_ignores_attempts_outside_window() -> None:
    """Five distinct usernames spread outside the window are not flagged."""
    events = [
        make_event(minute, username=f"user{index}")
        for index, minute in enumerate((0, 11, 12, 13, 14))
    ]

    assert detect_password_spraying(events) == []


def test_password_spraying_ignores_successful_logins() -> None:
    """Successful logins do not count toward password-spraying detection."""
    events = [
        make_event(
            minute,
            username=f"user{index}",
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
        for index, minute in enumerate(range(5))
    ]

    assert detect_password_spraying(events) == []


def test_password_spraying_groups_attempts_by_source_ip() -> None:
    """Different IP addresses must not combine their username counts."""
    events = [
        make_event(
            minute,
            source_ip="192.168.1.50",
            username=f"user{index}",
        )
        for index, minute in enumerate(range(3))
    ]
    events.extend(
        make_event(
            minute,
            source_ip="192.168.1.60",
            username=f"user{index}",
        )
        for index, minute in enumerate(range(3, 5))
    )

    assert detect_password_spraying(events) == []


def test_password_spraying_detects_at_window_boundary() -> None:
    """Five distinct usernames exactly ten minutes apart fit the window."""
    events = [
        make_event(minute, username=f"user{index}")
        for index, minute in enumerate((0, 2, 4, 6, 10))
    ]

    findings = detect_password_spraying(events)

    assert len(findings) == 1
    assert findings[0].attempt_count == 5


def test_password_spraying_returns_no_findings_for_empty_input() -> None:
    """An empty event list must produce no findings."""
    assert detect_password_spraying([]) == []


@pytest.mark.parametrize("username_threshold", [0, -1])
def test_password_spraying_rejects_invalid_threshold(
    username_threshold: int,
) -> None:
    """The distinct-username threshold must be positive."""
    with pytest.raises(ValueError, match="Username threshold"):
        detect_password_spraying(
            [],
            username_threshold=username_threshold,
        )


@pytest.mark.parametrize("window_minutes", [0, -1])
def test_password_spraying_rejects_invalid_window(
    window_minutes: int,
) -> None:
    """The password-spraying time window must be positive."""
    with pytest.raises(ValueError, match="Window"):
        detect_password_spraying(
            [],
            window_minutes=window_minutes,
        )


def test_success_after_failures_returns_one_finding_per_account_and_ip() -> None:
    """Return one finding despite multiple successful logins."""
    events = [make_event(minute) for minute in (0, 1, 2)]
    events.extend(
        make_event(
            minute,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
        for minute in (3, 4)
    )

    findings = detect_success_after_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "DET003"
    assert findings[0].source_ip == "192.168.1.50"


def test_success_after_failures_detects_multiple_accounts() -> None:
    """Detect suspicious successful logins for separate accounts."""
    events = [make_event(minute, username="alice") for minute in (0, 1, 2)]
    events.append(
        make_event(
            3,
            username="alice",
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )
    events.extend(make_event(minute, username="bob") for minute in (4, 5, 6))
    events.append(
        make_event(
            7,
            username="bob",
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    findings = detect_success_after_failed_logins(events)

    assert len(findings) == 2
    assert all(finding.rule_id == "DET003" for finding in findings)
    assert any("alice" in finding.description for finding in findings)
    assert any("bob" in finding.description for finding in findings)


def test_success_after_failures_requires_threshold() -> None:
    """Two failures followed by success must not meet the default threshold."""
    events = [make_event(minute) for minute in (0, 1)]
    events.append(
        make_event(
            2,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    assert detect_success_after_failed_logins(events) == []


def test_success_after_failures_ignores_old_failures() -> None:
    """Failures older than the configured window must not count."""
    events = [make_event(minute) for minute in (0, 1, 2)]
    events.append(
        make_event(
            13,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    assert detect_success_after_failed_logins(events) == []


def test_success_after_failures_includes_exact_window_boundary() -> None:
    """Include failures exactly at the configured time-window boundary."""
    events = [make_event(minute) for minute in (0, 1, 2)]
    events.append(
        make_event(
            10,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    findings = detect_success_after_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].attempt_count == 3
    assert findings[0].last_seen == BASE_TIME + timedelta(minutes=10)


def test_success_after_failures_excludes_failure_before_window_boundary() -> None:
    """Exclude failures just outside the configured time window."""
    events = [make_event(minute) for minute in (0, 1, 2)]
    events.append(
        make_event(
            12,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    findings = detect_success_after_failed_logins(events)

    assert findings == []


def test_success_after_failures_requires_same_username() -> None:
    """Failures for another username must not count toward the threshold."""
    events = [make_event(minute, username="alice") for minute in (0, 1, 2)]
    events.append(
        make_event(
            3,
            username="bob",
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    assert detect_success_after_failed_logins(events) == []


def test_success_after_failures_requires_same_source_ip() -> None:
    """Failures from another IP must not count toward the threshold."""
    events = [make_event(minute, source_ip="192.168.1.50") for minute in (0, 1, 2)]
    events.append(
        make_event(
            3,
            source_ip="192.168.1.60",
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    assert detect_success_after_failed_logins(events) == []


def test_success_after_failures_ignores_success_before_failures() -> None:
    """A success before failed attempts must not trigger this rule."""
    events = [
        make_event(
            0,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    ]
    events.extend(make_event(minute) for minute in (1, 2, 3))

    assert detect_success_after_failed_logins(events) == []


def test_success_after_failures_returns_no_findings_for_empty_input() -> None:
    """An empty event list must produce no findings."""
    assert detect_success_after_failed_logins([]) == []


@pytest.mark.parametrize("threshold", [0, -1])
def test_success_after_failures_rejects_invalid_threshold(
    threshold: int,
) -> None:
    """The successful-login detection threshold must be positive."""
    with pytest.raises(ValueError, match="Threshold"):
        detect_success_after_failed_logins([], threshold=threshold)


@pytest.mark.parametrize("window_minutes", [0, -1])
def test_success_after_failures_rejects_invalid_window(
    window_minutes: int,
) -> None:
    """The successful-login detection window must be positive."""
    with pytest.raises(ValueError, match="Window"):
        detect_success_after_failed_logins(
            [],
            window_minutes=window_minutes,
        )
