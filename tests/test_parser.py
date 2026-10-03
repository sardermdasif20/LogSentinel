"""Tests for LogSentinel log parsing."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from logsentinel.models import EventStatus, EventType
from logsentinel.parser import LogParserError, parse_log_line


def test_parse_valid_log_line() -> None:
    """Verify that a valid log line becomes a SecurityEvent."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | FAILURE | Invalid password"
    )

    event = parse_log_line(line)

    assert event.timestamp == datetime(
        2026, 10, 3, 8, 14, 22, tzinfo=timezone.utc
    )
    assert event.source == "server01"
    assert event.event_type is EventType.LOGIN_FAILURE
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.50"
    assert event.status is EventStatus.FAILURE
    assert event.message == "Invalid password"


def test_parse_connection_event_with_dash_username() -> None:
    """Verify that '-' is accepted when no user account applies."""
    line = (
        "2026-10-03T10:10:45Z | firewall01 | CONNECTION | "
        "- | 10.0.0.45 | INFO | Outbound connection established"
    )

    event = parse_log_line(line)

    assert event.event_type is EventType.CONNECTION
    assert event.username == "-"
    assert event.source_ip == "10.0.0.45"
    assert event.status is EventStatus.INFO


def test_parse_log_line_trims_field_whitespace() -> None:
    """Verify that surrounding field whitespace is removed."""
    line = (
        " 2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | FAILURE | Invalid password "
    )

    event = parse_log_line(line)

    assert event.source == "server01"
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.50"
    assert event.message == "Invalid password"


def test_parse_log_line_accepts_trailing_newline() -> None:
    """Verify that normal log line endings are handled."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | FAILURE | Invalid password\n"
    )

    event = parse_log_line(line)

    assert event.event_type is EventType.LOGIN_FAILURE


def test_parse_sample_log_file() -> None:
    """Verify that every line in the sample log parses successfully."""
    log_path = Path("examples/sample_security.log")

    lines = log_path.read_text(encoding="utf-8").splitlines()

    events = [parse_log_line(line) for line in lines]

    assert len(events) == 16
    assert events[0].event_type is EventType.LOGIN_SUCCESS
    assert events[1].event_type is EventType.LOGIN_FAILURE
    assert events[6].event_type is EventType.ACCOUNT_LOCK
    assert events[8].event_type is EventType.PRIVILEGE_CHANGE
    assert events[10].event_type is EventType.CONNECTION
    assert events[-1].event_type is EventType.FILE_ACCESS


def test_wrong_number_of_fields_raises_parser_error() -> None:
    """Verify that malformed field counts are rejected."""
    line = "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | alice"

    with pytest.raises(LogParserError, match="Expected 7 fields"):
        parse_log_line(line)


def test_invalid_timestamp_raises_parser_error() -> None:
    """Verify that invalid timestamps are rejected."""
    line = (
        "not-a-timestamp | server01 | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | FAILURE | Invalid password"
    )

    with pytest.raises(LogParserError, match="Invalid ISO 8601 timestamp"):
        parse_log_line(line)


def test_empty_source_raises_parser_error() -> None:
    """Verify that an empty source is rejected."""
    line = (
        "2026-10-03T08:14:22Z | | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | FAILURE | Invalid password"
    )

    with pytest.raises(LogParserError, match="Source cannot be empty"):
        parse_log_line(line)


def test_unsupported_event_type_raises_parser_error() -> None:
    """Verify that unsupported event types are rejected."""
    line = (
        "2026-10-03T08:14:22Z | server01 | UNKNOWN_EVENT | "
        "alice | 192.168.1.50 | FAILURE | Invalid password"
    )

    with pytest.raises(LogParserError, match="Unsupported event type"):
        parse_log_line(line)


def test_empty_username_raises_parser_error() -> None:
    """Verify that an empty username is rejected."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        " | 192.168.1.50 | FAILURE | Invalid password"
    )

    with pytest.raises(LogParserError, match="Username cannot be empty"):
        parse_log_line(line)


def test_invalid_ipv4_address_raises_parser_error() -> None:
    """Verify that invalid IPv4 addresses are rejected."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 999.999.999.999 | FAILURE | Invalid password"
    )

    with pytest.raises(LogParserError, match="Invalid IPv4 address"):
        parse_log_line(line)


def test_ipv6_address_raises_parser_error() -> None:
    """Verify that IPv6 is rejected in version one."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 2001:db8::1 | FAILURE | Invalid password"
    )

    with pytest.raises(LogParserError, match="Invalid IPv4 address"):
        parse_log_line(line)


def test_unsupported_status_raises_parser_error() -> None:
    """Verify that unsupported statuses are rejected."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | ERROR | Invalid password"
    )

    with pytest.raises(LogParserError, match="Unsupported status"):
        parse_log_line(line)


def test_empty_message_raises_parser_error() -> None:
    """Verify that an empty message is rejected."""
    line = (
        "2026-10-03T08:14:22Z | server01 | LOGIN_FAILURE | "
        "alice | 192.168.1.50 | FAILURE |"
    )

    with pytest.raises(LogParserError, match="Message cannot be empty"):
        parse_log_line(line)


def test_non_string_input_raises_parser_error() -> None:
    """Verify that non-string input is rejected."""
    with pytest.raises(LogParserError, match="Log line must be a string"):
        parse_log_line(None)  # type: ignore[arg-type]