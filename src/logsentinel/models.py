"""Data models used by LogSentinel."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class EventType(StrEnum):
    """Supported security event types."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    ACCOUNT_LOCK = "ACCOUNT_LOCK"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    PRIVILEGE_CHANGE = "PRIVILEGE_CHANGE"
    FILE_ACCESS = "FILE_ACCESS"
    CONNECTION = "CONNECTION"


class EventStatus(StrEnum):
    """Supported security event statuses."""

    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    INFO = "INFO"
    WARNING = "WARNING"


@dataclass(frozen=True)
class SecurityEvent:
    """Represent one structured security log event."""

    timestamp: datetime
    source: str
    event_type: EventType
    username: str
    source_ip: str
    status: EventStatus
    message: str