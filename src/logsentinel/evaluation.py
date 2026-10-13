"""Evaluate detection rules against labeled synthetic scenarios."""

from dataclasses import dataclass

from logsentinel.detector import (
    detect_password_spraying,
    detect_repeated_failed_logins,
    detect_success_after_failed_logins,
)
from logsentinel.models import SecurityEvent

SUPPORTED_RULES = ("DET001", "DET002", "DET003")


@dataclass(frozen=True)
class DetectionEvaluationCase:
    """A labeled scenario used to evaluate detection behavior."""

    name: str
    events: tuple[SecurityEvent, ...]
    expected_rule_ids: frozenset[str]


@dataclass(frozen=True)
class RuleMetrics:
    """Classification metrics for one detection rule."""

    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int

    @property
    def precision(self) -> float:
        """Return the fraction of positive predictions that were correct."""
        denominator = self.true_positives + self.false_positives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator

    @property
    def recall(self) -> float:
        """Return the fraction of expected positives that were detected."""
        denominator = self.true_positives + self.false_negatives
        if denominator == 0:
            return 0.0
        return self.true_positives / denominator

    @property
    def f1_score(self) -> float:
        """Return the harmonic mean of precision and recall."""
        denominator = self.precision + self.recall
        if denominator == 0:
            return 0.0
        return 2 * self.precision * self.recall / denominator


def _detected_rule_ids(events: list[SecurityEvent]) -> set[str]:
    """Run all supported rules and return the rule IDs that fired."""
    findings = (
        detect_repeated_failed_logins(events)
        + detect_password_spraying(events)
        + detect_success_after_failed_logins(events)
    )
    return {finding.rule_id for finding in findings}


def evaluate_detection_cases(
    cases: list[DetectionEvaluationCase],
) -> dict[str, RuleMetrics]:
    """Compare actual detector results with labeled expectations."""
    if not cases:
        raise ValueError("At least one evaluation case is required.")

    true_positives = dict.fromkeys(SUPPORTED_RULES, 0)
    false_positives = dict.fromkeys(SUPPORTED_RULES, 0)
    false_negatives = dict.fromkeys(SUPPORTED_RULES, 0)
    true_negatives = dict.fromkeys(SUPPORTED_RULES, 0)

    for case in cases:
        unknown_rules = case.expected_rule_ids - set(SUPPORTED_RULES)
        if unknown_rules:
            raise ValueError(
                f"Case '{case.name}' contains unsupported rule IDs: "
                f"{', '.join(sorted(unknown_rules))}"
            )

        actual = _detected_rule_ids(list(case.events))
        expected = case.expected_rule_ids

        for rule_id in SUPPORTED_RULES:
            was_expected = rule_id in expected
            was_detected = rule_id in actual

            if was_expected and was_detected:
                true_positives[rule_id] += 1
            elif was_detected:
                false_positives[rule_id] += 1
            elif was_expected:
                false_negatives[rule_id] += 1
            else:
                true_negatives[rule_id] += 1

    return {
        rule_id: RuleMetrics(
            true_positives=true_positives[rule_id],
            false_positives=false_positives[rule_id],
            false_negatives=false_negatives[rule_id],
            true_negatives=true_negatives[rule_id],
        )
        for rule_id in SUPPORTED_RULES
    }
