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


def _format_event_evidence(event: SecurityEvent) -> str:
    """Format the key fields of an event for a security finding."""
    username = event.username or "<unknown>"

    return (
        f"{event.timestamp.isoformat()} | "
        f"{event.event_type.value} | "
        f"status={event.status.value} | "
        f"username={username} | "
        f"source_ip={event.source_ip}"
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
            while event.timestamp - ordered_events[start].timestamp > window:
                start += 1

            matching_events = ordered_events[start : end + 1]

            if len(matching_events) >= threshold:
                affected_usernames = tuple(
                    sorted(
                        {
                            matching_event.username.strip()
                            for matching_event in matching_events
                            if (
                                matching_event.username
                                and matching_event.username.strip()
                            )
                        }
                    )
                )
                event_types = tuple(
                    sorted(
                        {
                            matching_event.event_type.value
                            for matching_event in matching_events
                        }
                    )
                )

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
                        evidence=tuple(
                            _format_event_evidence(matching_event)
                            for matching_event in matching_events
                        ),
                        affected_usernames=affected_usernames,
                        event_types=event_types,
                    )
                )
                break

    return findings


def detect_password_spraying(
    events: list[SecurityEvent],
    username_threshold: int = 5,
    window_minutes: int = 10,
) -> list[SecurityFinding]:
    """Detect failed login attempts against multiple usernames from one IP."""
    if username_threshold < 1:
        raise ValueError("Username threshold must be at least 1.")

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
            while event.timestamp - ordered_events[start].timestamp > window:
                start += 1

            matching_events = ordered_events[start : end + 1]
            unique_usernames = {
                matching_event.username.strip()
                for matching_event in matching_events
                if matching_event.username and matching_event.username.strip()
            }

            if len(unique_usernames) >= username_threshold:
                event_types = tuple(
                    sorted(
                        {
                            matching_event.event_type.value
                            for matching_event in matching_events
                        }
                    )
                )

                findings.append(
                    SecurityFinding(
                        rule_id="DET002",
                        rule_name="Possible Password Spraying",
                        severity=Severity.HIGH,
                        source_ip=source_ip,
                        attempt_count=len(matching_events),
                        window_minutes=window_minutes,
                        first_seen=matching_events[0].timestamp,
                        last_seen=matching_events[-1].timestamp,
                        description=(
                            f"Failed login attempts against "
                            f"{len(unique_usernames)} distinct usernames "
                            f"from {source_ip} within "
                            f"{window_minutes} minutes."
                        ),
                        evidence=tuple(
                            _format_event_evidence(matching_event)
                            for matching_event in matching_events
                        ),
                        affected_usernames=tuple(sorted(unique_usernames)),
                        event_types=event_types,
                    )
                )
                break

    return findings


def detect_success_after_failed_logins(
    events: list[SecurityEvent],
    threshold: int = 3,
    window_minutes: int = 10,
) -> list[SecurityFinding]:
    """Detect a successful login after repeated failures for the same account and IP."""
    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    if window_minutes < 1:
        raise ValueError("Window must be at least 1 minute.")

    failures_by_account: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    successes_by_account: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)

    for event in events:
        key = (event.source_ip, event.username)

        if (
            event.event_type == EventType.LOGIN_FAILURE
            and event.status == EventStatus.FAILURE
        ):
            failures_by_account[key].append(event)
        elif (
            event.event_type == EventType.LOGIN_SUCCESS
            and event.status == EventStatus.SUCCESS
        ):
            successes_by_account[key].append(event)

    findings: list[SecurityFinding] = []
    window = timedelta(minutes=window_minutes)

    for key, successes in successes_by_account.items():
        source_ip, username = key
        failures = sorted(
            failures_by_account.get(key, []),
            key=lambda event: event.timestamp,
        )
        ordered_successes = sorted(
            successes,
            key=lambda event: event.timestamp,
        )

        for success in ordered_successes:
            matching_failures = [
                failure
                for failure in failures
                if timedelta(0) < success.timestamp - failure.timestamp <= window
            ]

            if len(matching_failures) >= threshold:
                first_failure = matching_failures[0]
                evidence_events = [*matching_failures, success]

                event_types = tuple(
                    sorted(
                        {
                            matching_event.event_type.value
                            for matching_event in evidence_events
                        }
                    )
                )

                findings.append(
                    SecurityFinding(
                        rule_id="DET003",
                        rule_name="Successful Login After Repeated Failures",
                        severity=Severity.HIGH,
                        source_ip=source_ip,
                        attempt_count=len(matching_failures),
                        window_minutes=window_minutes,
                        first_seen=first_failure.timestamp,
                        last_seen=success.timestamp,
                        description=(
                            f"Successful login for username '{username}' "
                            f"from {source_ip} after "
                            f"{len(matching_failures)} failed login attempts "
                            f"within {window_minutes} minutes."
                        ),
                        evidence=tuple(
                            _format_event_evidence(matching_event)
                            for matching_event in evidence_events
                        ),
                        affected_usernames=(username,) if username else (),
                        event_types=event_types,
                    )
                )
                break

    return findings
