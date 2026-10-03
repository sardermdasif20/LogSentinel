"""Parser for LogSentinel security log lines."""

from datetime import datetime
from ipaddress import IPv4Address

from logsentinel.models import EventStatus, EventType, SecurityEvent


class LogParserError(Exception):
    """Raised when a log line cannot be parsed into a valid security event."""


def parse_log_line(line: str) -> SecurityEvent:
    """Parse one raw log line into a SecurityEvent."""
    if not isinstance(line, str):
        raise LogParserError("Log line must be a string.")

    line = line.rstrip("\r\n")
    fields = [field.strip() for field in line.split("|")]

    if len(fields) != 7:
        raise LogParserError(
            f"Expected 7 fields, but found {len(fields)}."
        )

    (
        timestamp_text,
        source,
        event_type_text,
        username,
        source_ip,
        status_text,
        message,
    ) = fields

    if not timestamp_text:
        raise LogParserError("Timestamp cannot be empty.")

    try:
        timestamp = datetime.fromisoformat(
            timestamp_text.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise LogParserError(
            f"Invalid ISO 8601 timestamp: {timestamp_text}"
        ) from exc

    if not source:
        raise LogParserError("Source cannot be empty.")

    try:
        event_type = EventType(event_type_text)
    except ValueError as exc:
        raise LogParserError(
            f"Unsupported event type: {event_type_text}"
        ) from exc

    if not username:
        raise LogParserError("Username cannot be empty.")

    try:
        IPv4Address(source_ip)
    except ValueError as exc:
        raise LogParserError(
            f"Invalid IPv4 address: {source_ip}"
        ) from exc

    try:
        status = EventStatus(status_text)
    except ValueError as exc:
        raise LogParserError(
            f"Unsupported status: {status_text}"
        ) from exc

    if not message:
        raise LogParserError("Message cannot be empty.")

    return SecurityEvent(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        status=status,
        message=message,
    )