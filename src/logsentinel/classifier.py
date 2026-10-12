"""Default severity classification for security events."""

from logsentinel.models import EventType, SecurityEvent, Severity


_DEFAULT_SEVERITY: dict[EventType, Severity] = {
    EventType.LOGIN_SUCCESS: Severity.INFO,
    EventType.LOGIN_FAILURE: Severity.WARNING,
    EventType.ACCOUNT_LOCK: Severity.HIGH,
    EventType.PASSWORD_CHANGE: Severity.INFO,
    EventType.PRIVILEGE_CHANGE: Severity.HIGH,
    EventType.FILE_ACCESS: Severity.INFO,
    EventType.CONNECTION: Severity.INFO,
}


def classify_event(event: SecurityEvent) -> Severity:
    """Return the default severity assigned to a security event."""
    try:
        return _DEFAULT_SEVERITY[event.event_type]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported event type: {event.event_type}"
        ) from exc
