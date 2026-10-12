"""Tests for LogSentinel security analytics."""

from datetime import UTC, datetime

import pytest

from logsentinel.analytics import (
    build_analytics_report,
    count_events_by_source_ip,
    count_events_by_status,
    count_events_by_type,
    count_findings_by_rule,
    count_findings_by_severity,
    get_top_source_ips,
)
from logsentinel.models import (
    EventStatus,
    EventType,
    SecurityEvent,
    SecurityFinding,
    Severity,
)


@pytest.fixture
def sample_events() -> list[SecurityEvent]:
    timestamp = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)

    return [
        SecurityEvent(
            timestamp=timestamp,
            source="server01",
            event_type=EventType.LOGIN_FAILURE,
            username="alice",
            source_ip="192.168.1.10",
            status=EventStatus.FAILURE,
            message="Login failed",
        ),
        SecurityEvent(
            timestamp=timestamp,
            source="server01",
            event_type=EventType.LOGIN_FAILURE,
            username="bob",
            source_ip="192.168.1.10",
            status=EventStatus.FAILURE,
            message="Login failed",
        ),
        SecurityEvent(
            timestamp=timestamp,
            source="server02",
            event_type=EventType.LOGIN_SUCCESS,
            username="alice",
            source_ip="192.168.1.20",
            status=EventStatus.SUCCESS,
            message="Login successful",
        ),
        SecurityEvent(
            timestamp=timestamp,
            source="server01",
            event_type=EventType.FILE_ACCESS,
            username="carol",
            source_ip="192.168.1.30",
            status=EventStatus.WARNING,
            message="Unusual file access",
        ),
    ]


@pytest.fixture
def sample_findings() -> list[SecurityFinding]:
    timestamp = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)

    return [
        SecurityFinding(
            rule_id="DET001",
            rule_name="Repeated Failed Logins",
            severity=Severity.HIGH,
            source_ip="192.168.1.10",
            attempt_count=5,
            window_minutes=10,
            first_seen=timestamp,
            last_seen=timestamp,
            description="Repeated login failures detected.",
        ),
        SecurityFinding(
            rule_id="DET001",
            rule_name="Repeated Failed Logins",
            severity=Severity.HIGH,
            source_ip="192.168.1.20",
            attempt_count=4,
            window_minutes=10,
            first_seen=timestamp,
            last_seen=timestamp,
            description="Repeated login failures detected.",
        ),
        SecurityFinding(
            rule_id="DET003",
            rule_name="Successful Login After Repeated Failures",
            severity=Severity.HIGH,
            source_ip="192.168.1.10",
            attempt_count=3,
            window_minutes=10,
            first_seen=timestamp,
            last_seen=timestamp,
            description="Successful login followed repeated failures.",
        ),
    ]


def test_count_events_by_type(sample_events):
    assert count_events_by_type(sample_events) == {
        "FILE_ACCESS": 1,
        "LOGIN_FAILURE": 2,
        "LOGIN_SUCCESS": 1,
    }


def test_count_events_by_status(sample_events):
    assert count_events_by_status(sample_events) == {
        "FAILURE": 2,
        "SUCCESS": 1,
        "WARNING": 1,
    }


def test_count_events_by_source_ip(sample_events):
    assert count_events_by_source_ip(sample_events) == {
        "192.168.1.10": 2,
        "192.168.1.20": 1,
        "192.168.1.30": 1,
    }


def test_get_top_source_ips_orders_by_count(sample_events):
    assert get_top_source_ips(sample_events, limit=2) == [
        {"source_ip": "192.168.1.10", "event_count": 2},
        {"source_ip": "192.168.1.20", "event_count": 1},
    ]


def test_get_top_source_ips_breaks_ties_by_ip(sample_events):
    assert get_top_source_ips(sample_events, limit=3) == [
        {"source_ip": "192.168.1.10", "event_count": 2},
        {"source_ip": "192.168.1.20", "event_count": 1},
        {"source_ip": "192.168.1.30", "event_count": 1},
    ]


def test_get_top_source_ips_rejects_invalid_limit(sample_events):
    with pytest.raises(ValueError, match="limit must be at least 1"):
        get_top_source_ips(sample_events, limit=0)


def test_count_findings_by_severity(sample_findings):
    assert count_findings_by_severity(sample_findings) == {
        "HIGH": 3,
    }


def test_count_findings_by_rule(sample_findings):
    assert count_findings_by_rule(sample_findings) == {
        "DET001": 2,
        "DET003": 1,
    }


def test_build_analytics_report(sample_events, sample_findings):
    report = build_analytics_report(
        sample_events,
        sample_findings,
        top_ip_limit=2,
    )

    assert report["total_events"] == 4
    assert report["total_findings"] == 3
    assert report["unique_source_ips"] == 3
    assert report["events_by_type"]["LOGIN_FAILURE"] == 2
    assert report["findings_by_rule"]["DET001"] == 2
    assert len(report["top_source_ips"]) == 2


def test_build_analytics_report_handles_empty_input():
    report = build_analytics_report([], [])

    assert report["total_events"] == 0
    assert report["total_findings"] == 0
    assert report["unique_source_ips"] == 0
    assert report["events_by_type"] == {}
    assert report["events_by_status"] == {}
    assert report["events_by_source_ip"] == {}
    assert report["top_source_ips"] == []
    assert report["findings_by_severity"] == {}
    assert report["findings_by_rule"] == {}


def test_build_analytics_report_rejects_invalid_limit():
    with pytest.raises(ValueError, match="top_ip_limit must be at least 1"):
        build_analytics_report([], [], top_ip_limit=0)
