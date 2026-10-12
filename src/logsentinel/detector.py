"""Rule-based detection of suspicious security events."""

from collections import defaultdict
from datetime import timedelta

from logsentinel.models import (
    EventStatus,
    EventType,
    SecurityEvent,
    SecurityFinding,
    Severity,
)


def detect_repeated_failed_logins(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[SecurityFinding]:
    """Detect IP addresses with repeated failed logins in a time window."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Window must be at least 1 minute.")

    failed_logins: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if (
            event.event_type == EventType.LOGIN_FAILURE
            and event.status == EventStatus.FAILURE
        ):
            failed_logins[event.source_ip].append(event)

    findings: list[SecurityFinding] = []
    window = timedelta(minutes=window_minutes)

    for source_ip, ip_events in failed_logins.items():
        ordered_events = sorted(
            ip_events,
            key=lambda event: event.timestamp,
        )

        start = 0

        for end, event in enumerate(ordered_events):
            while (
                event.timestamp - ordered_events[start].timestamp
                > window
            ):
                start += 1

            matching_events = ordered_events[start : end + 1]

            if len(matching_events) >= threshold:
                findings.append(
                    SecurityFinding(
                        rule_id="DET001",
                        rule_name="Repeated Failed Logins",
                        severity=Severity.HIGH,
                        source_ip=source_ip,
                        attempt_count=len(matching_events),
                        window_minutes=window_minutes,
                        first_seen=matching_events[0].timestamp,
                        last_seen=matching_events[-1].timestamp,
                        description=(
                            f"{len(matching_events)} failed login attempts "
                            f"from {source_ip} within "
                            f"{window_minutes} minutes."
                        ),
                    )
                )
                break

    return findings
