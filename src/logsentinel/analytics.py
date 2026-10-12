"""Security event and detection finding analytics."""

from collections import Counter
from collections.abc import Iterable

from logsentinel.models import SecurityEvent, SecurityFinding


def count_events_by_type(
    events: Iterable[SecurityEvent],
) -> dict[str, int]:
    """Count security events by event type."""
    counts = Counter(event.event_type.value for event in events)
    return dict(sorted(counts.items()))


def count_events_by_status(
    events: Iterable[SecurityEvent],
) -> dict[str, int]:
    """Count security events by status."""
    counts = Counter(event.status.value for event in events)
    return dict(sorted(counts.items()))


def count_events_by_source_ip(
    events: Iterable[SecurityEvent],
) -> dict[str, int]:
    """Count events associated with each source IP."""
    counts = Counter(event.source_ip for event in events)
    return dict(sorted(counts.items()))


def get_top_source_ips(
    events: Iterable[SecurityEvent],
    limit: int = 5,
) -> list[dict[str, int | str]]:
    """Return the most active source IP addresses."""
    if limit < 1:
        raise ValueError("limit must be at least 1")

    counts = Counter(event.source_ip for event in events)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))

    return [
        {"source_ip": source_ip, "event_count": count}
        for source_ip, count in ordered[:limit]
    ]


def count_findings_by_severity(
    findings: Iterable[SecurityFinding],
) -> dict[str, int]:
    """Count findings by severity."""
    counts = Counter(finding.severity.value for finding in findings)
    return dict(sorted(counts.items()))


def count_findings_by_rule(
    findings: Iterable[SecurityFinding],
) -> dict[str, int]:
    """Count findings by detection rule ID."""
    counts = Counter(finding.rule_id for finding in findings)
    return dict(sorted(counts.items()))


def build_analytics_report(
    events: Iterable[SecurityEvent],
    findings: Iterable[SecurityFinding],
    top_ip_limit: int = 5,
) -> dict[str, object]:
    """Build a combined analytics report."""
    if top_ip_limit < 1:
        raise ValueError("top_ip_limit must be at least 1")

    event_list = list(events)
    finding_list = list(findings)

    return {
        "total_events": len(event_list),
        "total_findings": len(finding_list),
        "unique_source_ips": len(
            {event.source_ip for event in event_list}
        ),
        "events_by_type": count_events_by_type(event_list),
        "events_by_status": count_events_by_status(event_list),
        "events_by_source_ip": count_events_by_source_ip(event_list),
        "top_source_ips": get_top_source_ips(
            event_list,
            limit=top_ip_limit,
        ),
        "findings_by_severity": count_findings_by_severity(
            finding_list
        ),
        "findings_by_rule": count_findings_by_rule(finding_list),
    }
