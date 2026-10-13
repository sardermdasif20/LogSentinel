"""Tests for evaluating LogSentinel detection quality."""

from datetime import UTC, datetime, timedelta

import pytest

from logsentinel.evaluation import (
    DetectionEvaluationCase,
    RuleMetrics,
    evaluate_detection_cases,
)
from logsentinel.models import EventStatus, EventType, SecurityEvent

BASE_TIME = datetime(2026, 10, 12, 10, 0, tzinfo=UTC)
SOURCE_IP = "192.0.2.10"


def make_event(
    minute: int,
    username: str = "alice",
    event_type: EventType = EventType.LOGIN_FAILURE,
    status: EventStatus = EventStatus.FAILURE,
) -> SecurityEvent:
    """Build a synthetic authentication event."""
    return SecurityEvent(
        timestamp=BASE_TIME + timedelta(minutes=minute),
        source="evaluation-test",
        event_type=event_type,
        username=username,
        source_ip=SOURCE_IP,
        status=status,
        message="Synthetic evaluation event",
    )


def make_case(
    name: str,
    events: list[SecurityEvent],
    expected_rule_ids: set[str],
) -> DetectionEvaluationCase:
    """Build one labeled evaluation scenario."""
    return DetectionEvaluationCase(
        name=name,
        events=tuple(events),
        expected_rule_ids=frozenset(expected_rule_ids),
    )


def test_evaluation_counts_correct_detections() -> None:
    """Correctly detected and benign scenarios should be counted."""
    repeated_failures = [make_event(minute, username="alice") for minute in range(5)]
    benign_activity = [make_event(0), make_event(1)]

    cases = [
        make_case("repeated failures", repeated_failures, {"DET001"}),
        make_case("benign activity", benign_activity, set()),
    ]

    results = evaluate_detection_cases(cases)

    det001 = results["DET001"]
    assert det001.true_positives == 1
    assert det001.false_positives == 0
    assert det001.false_negatives == 0
    assert det001.true_negatives == 1
    assert det001.precision == 1.0
    assert det001.recall == 1.0
    assert det001.f1_score == 1.0


def test_evaluation_reports_false_positives_and_false_negatives() -> None:
    """Incorrect labels expose both missed and unexpected detections."""
    detected_but_labeled_benign = [
        make_event(minute, username="alice") for minute in range(5)
    ]
    expected_but_missed = [make_event(0), make_event(1)]

    cases = [
        make_case("unexpected detection", detected_but_labeled_benign, set()),
        make_case("missed detection", expected_but_missed, {"DET001"}),
    ]

    det001 = evaluate_detection_cases(cases)["DET001"]

    assert det001.true_positives == 0
    assert det001.false_positives == 1
    assert det001.false_negatives == 1
    assert det001.true_negatives == 0
    assert det001.precision == 0.0
    assert det001.recall == 0.0
    assert det001.f1_score == 0.0


def test_evaluation_identifies_password_spraying() -> None:
    """Distinct usernames should trigger the password-spraying rule."""
    events = [
        make_event(minute, username=f"user{index}")
        for index, minute in enumerate(range(5))
    ]
    case = make_case(
        "password spraying",
        events,
        {"DET001", "DET002"},
    )

    results = evaluate_detection_cases([case])

    assert results["DET002"].true_positives == 1
    assert results["DET002"].false_negatives == 0


def test_evaluation_identifies_success_after_failures() -> None:
    """Three failures followed by success should trigger DET003."""
    events = [make_event(minute) for minute in (0, 1, 2)]
    events.append(
        make_event(
            3,
            event_type=EventType.LOGIN_SUCCESS,
            status=EventStatus.SUCCESS,
        )
    )
    case = make_case(
        "successful login after failures",
        events,
        {"DET003"},
    )

    results = evaluate_detection_cases([case])

    assert results["DET003"].true_positives == 1
    assert results["DET003"].false_negatives == 0


def test_evaluation_rejects_empty_dataset() -> None:
    """An empty evaluation set cannot provide useful metrics."""
    with pytest.raises(ValueError, match="At least one"):
        evaluate_detection_cases([])


def test_evaluation_rejects_unknown_expected_rule() -> None:
    """Typos in rule labels should not silently distort metrics."""
    case = make_case("invalid label", [], {"DET999"})

    with pytest.raises(ValueError, match="unsupported rule IDs"):
        evaluate_detection_cases([case])


def test_metrics_return_zero_when_no_positive_predictions() -> None:
    """Undefined precision, recall, and F1 are represented as zero."""
    metrics = RuleMetrics(
        true_positives=0,
        false_positives=0,
        false_negatives=0,
        true_negatives=4,
    )

    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1_score == 0.0
