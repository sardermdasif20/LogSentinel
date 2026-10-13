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
    username: str | None = "alice",
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


def test_det001_reports_unique_affected_usernames_and_event_types() -> None:
    """DET001 should report sorted, unique usernames and event types."""
    events = [
        make_event(0, username="bob"),
        make_event(1, username="alice"),
        make_event(2, username="bob"),
        make_event(3, username="charlie"),
        make_event(4, username="alice"),
    ]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].affected_usernames == ("alice", "bob", "charlie")
    assert findings[0].event_types == ("LOGIN_FAILURE",)


def test_det001_handles_missing_usernames_in_structured_fields() -> None:
    """DET001 should omit missing usernames from affected-user lists."""
    events = [
        make_event(0, username=None),
        make_event(1, username="alice"),
        make_event(2, username=None),
        make_event(3, username="bob"),
        make_event(4, username="alice"),
    ]

    findings = detect_repeated_failed_logins(events)

    assert len(findings) == 1
    assert findings[0].affected_usernames == ("alice", "bob")
    assert findings[0].event_types == ("LOGIN_FAILURE",)


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
    assert all(f"user{index}" in " ".join(finding.evidence) for index in range(5))


def test_det002_reports_sorted_distinct_usernames_and_event_types() -> None:
    """DET002 should report every affected username exactly once."""
    events = [
        make_event(0, username="zoe"),
        make_event(1, username="alice"),
        make_event(2, username="bob"),
        make_event(3, username="alice"),
        make_event(4, username="zoe"),
        make_event(5, username="charlie"),
        make_event(6, username="dana"),
    ]

    findings = detect_password_spraying(events)

    assert len(findings) == 1
    assert findings[0].affected_usernames == ("alice", "bob", "charlie", "dana", "zoe")
    assert findings[0].event_types == ("LOGIN_FAILURE",)


def test_det002_normalizes_whitespace_in_structured_usernames() -> None:
    """Whitespace variants should not become separate affected usernames."""
    events = [
        make_event(0, username="zoe"),
        make_event(1, username="alice"),
        make_event(2, username="bob"),
        make_event(3, username="alice"),
        make_event(4, username="zoe"),
        make_event(5, username="charlie"),
        make_event(6, username="dana"),
    ]

    findings = detect_password_spraying(events)

    assert len(findings) == 1
    assert findings[0].affected_usernames == (
        "alice",
        "bob",
        "charlie",
        "dana",
        "zoe",
    )


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


def test_det003_reports_account_and_both_login_event_types() -> None:
    """DET003 should identify the affected account and failure/success types."""
    events = [make_event(minute, username="alice") for minute in (0, 1, 2)]
    events.append(
        make_event(
            3,
            username="alice",
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )

    findings = detect_success_after_failed_logins(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.affected_usernames == ("alice",)
    assert finding.event_types == ("LOGIN_FAILURE", "LOGIN_SUCCESS")
    assert len(finding.evidence) == 4


def test_det003_does_not_include_unrelated_accounts_in_evidence() -> None:
    """DET003 evidence should only describe the matching account and IP."""
    events = [make_event(minute, username="alice") for minute in (0, 1, 2)]
    events.extend(
        [
            make_event(2, username="bob"),
            make_event(
                3,
                username="alice",
                event_type=EventType.LOGIN_SUCCESS,
                status=EventStatus.SUCCESS,
            ),
        ]
    )

    findings = detect_success_after_failed_logins(events)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.affected_usernames == ("alice",)
    assert all("username=alice" in item for item in finding.evidence)
